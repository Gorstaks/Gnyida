using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Gnyida.Core
{
    /// <summary>
    /// Compares the read-only executable sections of a PE file on disk with the same range in a running
    /// process, ignoring bytes the loader legitimately rewrites (base relocations and the IAT).
    ///
    /// Why: process hollowing and image replacement leave the process object pointing at a genuine signed
    /// file (the Authenticode check passes) while the code in memory is different. This is the
    /// "KNOWN LIMITATION" recorded in <see cref="EtwThreatIntelMonitor"/>: the replaced code is still
    /// MEM_IMAGE, so unbacked-RWX scanning never sees it.
    ///
    /// Design constraints (see docs/MEMORY_LEAK_3.7.8.md): no async waits, no static state, fixed 4 KB
    /// buffers (nothing near the 85 KB large-object threshold), no collection that grows with the input.
    /// The memory source is a delegate so the comparison is unit-testable without a live process.
    /// </summary>
    internal static class ImageIntegrityVerifier
    {
        internal enum Verdict { Clean, Incomparable, HeaderMismatch, CodeReplaced, EntryPointPatched }

        /// <summary>Reads <paramref name="count"/> bytes at the image-relative address into the buffer.</summary>
        internal delegate bool ReadMemory(uint rva, byte[] buffer, int count);

        internal sealed class Result
        {
            public bool Comparable;
            public string Reason = "";
            public bool HeaderMismatch;
            public long ComparedBytes;
            public long DifferingBytes;
            public int LongestDifferingRun;
            public int EntryPointDifferingBytes;
            /// <summary>64-byte blocks in which at least 48 bytes differ: a payload-sized replacement, not a hook.</summary>
            public int DenseBlocks;
            public int TotalPages;
            public int UnreadablePages;
            public string? FirstDifferingSection;
        }

        private const int Page = 4096;
        private const uint ExecuteFlag = 0x20000000;
        private const uint WriteFlag = 0x80000000;
        private const int EntryPointWindow = 64;
        /// <summary>Upper bound on bytes compared for one image, so a huge binary cannot stall a scan.</summary>
        internal const long MaxCompareBytes = 24L * 1024 * 1024;

        // A differing run of this many contiguous bytes, or this share of compared bytes, means the code was
        // replaced. Loader work such as import optimization patches a few bytes at scattered call sites and
        // stays far below both.
        internal const int ReplacedRunBytes = 4096;
        internal const int ReplacedPercent = 10;
        internal const int EntryPointPatchedBytes = 8;
        // Inline hooks (Detours, AV or overlay trampolines) change 5 to 32 bytes at a time. A payload written over
        // code changes nearly every byte of each 64-byte block it covers, so 4 such blocks (256 bytes) is not a hook.
        internal const int DenseBlockBytes = 48;
        internal const int DenseBlocksReplaced = 4;

        private struct Section
        {
            public string Name;
            public uint VirtualAddress, VirtualSize, RawSize, RawPointer, Characteristics;
            public uint CompareLength;
        }

        internal static Verdict Classify(Result r)
        {
            if (!r.Comparable) return Verdict.Incomparable;
            if (r.HeaderMismatch) return Verdict.HeaderMismatch;
            if (r.ComparedBytes < Page) return Verdict.Incomparable;
            // Mostly unreadable means we did not really compare; do not call that clean or bad.
            if (r.TotalPages > 0 && r.UnreadablePages * 2 > r.TotalPages) return Verdict.Incomparable;
            if (r.LongestDifferingRun >= ReplacedRunBytes || r.DenseBlocks >= DenseBlocksReplaced ||
                r.DifferingBytes * 100 >= r.ComparedBytes * ReplacedPercent)
                return Verdict.CodeReplaced;
            if (r.EntryPointDifferingBytes >= EntryPointPatchedBytes) return Verdict.EntryPointPatched;
            return Verdict.Clean;
        }

        internal static Result Compare(Stream disk, ReadMemory memory)
        {
            var result = new Result();
            try { return CompareCore(disk, memory, result); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException || ex is ArgumentException)
            {
                result.Comparable = false;
                result.Reason = "read error: " + ex.Message;
                return result;
            }
        }

        private static Result Fail(Result r, string reason)
        {
            r.Comparable = false;
            r.Reason = reason;
            return r;
        }

        private static Result CompareCore(Stream disk, ReadMemory memory, Result r)
        {
            var hdr = new byte[Page];
            int hn = ReadAt(disk, 0, hdr, Page);
            if (hn < 0x100 || hdr[0] != (byte)'M' || hdr[1] != (byte)'Z') return Fail(r, "not a PE file");
            int pe = BitConverter.ToInt32(hdr, 0x3C);
            if (pe < 0x40 || pe > hn - 0x100 || U32(hdr, pe) != 0x00004550) return Fail(r, "bad PE signature");

            ushort machine = U16(hdr, pe + 4);
            int nSec = U16(hdr, pe + 6);
            uint timestamp = U32(hdr, pe + 8);
            int optSize = U16(hdr, pe + 20);
            int opt = pe + 24;
            ushort magic = U16(hdr, opt);
            bool pe64 = magic == 0x20B;
            if (!((machine == 0x8664 && pe64) || (machine == 0x14C && magic == 0x10B))) return Fail(r, "unsupported machine type");
            if (nSec == 0 || nSec > 96) return Fail(r, "bad section count");
            int secTable = opt + optSize;
            if (optSize < 96 || secTable + nSec * 40 > hn) return Fail(r, "headers extend past the first page");

            uint entryPoint = U32(hdr, opt + 16);
            uint sectionAlignment = U32(hdr, opt + 32);
            uint sizeOfImage = U32(hdr, opt + 56);
            if (sectionAlignment < Page) return Fail(r, "section alignment below page size");
            int dirBase = pe64 ? opt + 112 : opt + 96;
            uint numDirs = U32(hdr, pe64 ? opt + 108 : opt + 92);
            if (dirBase + (long)numDirs * 8 > opt + optSize) numDirs = (uint)Math.Max(0, (opt + optSize - dirBase) / 8);
            uint relocRva = 0, relocSize = 0, iatRva = 0, iatSize = 0;
            if (numDirs > 5) { relocRva = U32(hdr, dirBase + 40); relocSize = U32(hdr, dirBase + 44); }
            if (numDirs > 12) { iatRva = U32(hdr, dirBase + 96); iatSize = U32(hdr, dirBase + 100); }

            var sections = new Section[nSec];
            for (int i = 0; i < nSec; i++)
            {
                int o = secTable + i * 40;
                sections[i] = new Section
                {
                    Name = Encoding.ASCII.GetString(hdr, o, 8).TrimEnd('\0'),
                    VirtualSize = U32(hdr, o + 8),
                    VirtualAddress = U32(hdr, o + 12),
                    RawSize = U32(hdr, o + 16),
                    RawPointer = U32(hdr, o + 20),
                    Characteristics = U32(hdr, o + 36),
                };
            }

            // Header check: a process whose image was swapped has different headers in memory even though
            // its image path still names the original file. Only fields the loader never rewrites are compared
            // (not ImageBase, which the loader updates for a relocated image).
            var mem = new byte[Page];
            if (!memory(0, mem, Page)) return Fail(r, "image header unreadable in memory");
            r.Comparable = true;
            if (U32(mem, pe) != 0x00004550 || U16(mem, pe + 4) != machine || U16(mem, pe + 6) != nSec ||
                U32(mem, pe + 8) != timestamp || U32(mem, opt + 16) != entryPoint || U32(mem, opt + 56) != sizeOfImage)
            {
                r.HeaderMismatch = true;
                r.Reason = "PE header fields in memory differ from the file";
                return r;
            }
            for (int i = 0; i < nSec; i++)
            {
                int o = secTable + i * 40;
                if (U32(mem, o + 8) != sections[i].VirtualSize || U32(mem, o + 12) != sections[i].VirtualAddress ||
                    U32(mem, o + 36) != sections[i].Characteristics)
                {
                    r.HeaderMismatch = true;
                    r.Reason = "section table in memory differs from the file";
                    return r;
                }
            }

            // Executable, non-writable, file-backed sections, in address order.
            var exec = new List<Section>();
            long total = 0;
            for (int i = 0; i < nSec; i++)
            {
                Section s = sections[i];
                if ((s.Characteristics & ExecuteFlag) == 0 || (s.Characteristics & WriteFlag) != 0) continue;
                if (s.RawPointer == 0 || s.RawSize == 0) continue;
                uint size = s.VirtualSize == 0 ? s.RawSize : Math.Min(s.VirtualSize, s.RawSize);
                if (s.VirtualAddress % Page != 0) return Fail(r, "section not page aligned");
                s.CompareLength = size;
                total += size;
                exec.Add(s);
            }
            if (exec.Count == 0) return Fail(r, "no executable file-backed section");
            if (total > MaxCompareBytes) return Fail(r, "executable sections exceed the compare limit");
            exec.Sort((a, b) => a.VirtualAddress.CompareTo(b.VirtualAddress));

            var cursor = new RelocCursor(disk);
            if (relocSize > 0)
            {
                long relocOffset = RvaToFileOffset(sections, relocRva);
                if (relocOffset < 0) return Fail(r, "relocation directory is not file backed");
                cursor.Start(relocOffset, relocSize);
            }

            var diskBuf = new byte[Page];
            var memBuf = new byte[Page];
            var mask = new bool[Page];
            uint carryPage = 0;
            int carryLength = 0;

            foreach (Section s in exec)
            {
                int run = 0;
                for (uint off = 0; off < s.CompareLength; off += Page)
                {
                    uint pageRva = s.VirtualAddress + off;
                    int n = (int)Math.Min((uint)Page, s.CompareLength - off);
                    r.TotalPages++;

                    Array.Clear(mask, 0, Page);
                    if (carryLength > 0 && carryPage == pageRva)
                        for (int i = 0; i < carryLength && i < Page; i++) mask[i] = true;
                    carryLength = 0;

                    while (cursor.Have && cursor.PageRva < pageRva) cursor.Next();
                    if (cursor.Have && cursor.PageRva == pageRva)
                    {
                        for (int k = 0; k < cursor.Count; k++)
                        {
                            ushort e = U16(cursor.Entries, k * 2);
                            int type = e >> 12;
                            int at = e & 0x0FFF;
                            int len;
                            switch (type)
                            {
                                case 0: len = 0; break;          // ABSOLUTE (padding)
                                case 1: case 2: len = 2; break;  // HIGH, LOW
                                case 3: len = 4; break;          // HIGHLOW
                                case 10: len = 8; break;         // DIR64
                                default: return Fail(r, "unsupported relocation type " + type);
                            }
                            for (int b = 0; b < len; b++)
                            {
                                int idx = at + b;
                                if (idx < Page) mask[idx] = true;
                            }
                            if (at + len > Page)
                            {
                                carryPage = pageRva + Page;
                                carryLength = Math.Max(carryLength, at + len - Page);
                            }
                        }
                    }
                    if (iatSize > 0 && iatRva < pageRva + Page && iatRva + iatSize > pageRva)
                    {
                        long from = Math.Max(0, (long)iatRva - pageRva);
                        long to = Math.Min(Page, (long)iatRva + iatSize - pageRva);
                        for (long i = from; i < to; i++) mask[i] = true;
                    }

                    if (ReadAt(disk, (long)s.RawPointer + off, diskBuf, n) != n) return Fail(r, "file is shorter than its section table claims");
                    if (!memory(pageRva, memBuf, n))
                    {
                        r.UnreadablePages++;
                        run = 0;
                        continue;
                    }
                    int blockDiff = 0;
                    for (int i = 0; i < n; i++)
                    {
                        if ((i & 63) == 0) blockDiff = 0;
                        if (mask[i]) continue;
                        r.ComparedBytes++;
                        if (diskBuf[i] != memBuf[i])
                        {
                            r.DifferingBytes++;
                            if (++blockDiff == DenseBlockBytes) r.DenseBlocks++;
                            run++;
                            if (run > r.LongestDifferingRun) r.LongestDifferingRun = run;
                            uint rva = pageRva + (uint)i;
                            if (rva >= entryPoint && rva < entryPoint + EntryPointWindow) r.EntryPointDifferingBytes++;
                            if (r.FirstDifferingSection == null) r.FirstDifferingSection = s.Name;
                        }
                        else
                        {
                            run = 0;
                        }
                    }
                }
            }
            return r;
        }

        /// <summary>Walks IMAGE_BASE_RELOCATION blocks with a fixed-size buffer; blocks are sorted by page.</summary>
        private sealed class RelocCursor
        {
            private readonly Stream _stream;
            private long _position;
            private long _end;
            private readonly byte[] _header = new byte[8];
            public readonly byte[] Entries = new byte[8192];
            public bool Have;
            public uint PageRva;
            public int Count;

            public RelocCursor(Stream stream) { _stream = stream; }

            public void Start(long offset, uint size)
            {
                _position = offset;
                _end = offset + size;
                Next();
            }

            public void Next()
            {
                Have = false;
                if (_position + 8 > _end) return;
                if (ReadAt(_stream, _position, _header, 8) != 8) throw new InvalidDataException("truncated relocation block header");
                uint page = BitConverter.ToUInt32(_header, 0);
                uint size = BitConverter.ToUInt32(_header, 4);
                if (size == 0) return; // zero padding at the end of the directory
                if (size < 8 || size > 8 + Entries.Length || ((size - 8) & 1) != 0 || _position + size > _end)
                    throw new InvalidDataException("malformed relocation block");
                int payload = (int)size - 8;
                if (ReadAt(_stream, _position + 8, Entries, payload) != payload) throw new InvalidDataException("truncated relocation block");
                _position += size;
                PageRva = page;
                Count = payload / 2;
                Have = true;
            }
        }

        private static long RvaToFileOffset(Section[] sections, uint rva)
        {
            foreach (Section s in sections)
            {
                if (rva >= s.VirtualAddress && rva - s.VirtualAddress < s.RawSize && s.RawPointer != 0)
                    return (long)s.RawPointer + (rva - s.VirtualAddress);
            }
            return -1;
        }

        private static int ReadAt(Stream stream, long offset, byte[] buffer, int count)
        {
            if (offset < 0 || offset > stream.Length) return 0;
            stream.Seek(offset, SeekOrigin.Begin);
            int total = 0;
            while (total < count)
            {
                int got = stream.Read(buffer, total, count - total);
                if (got <= 0) break;
                total += got;
            }
            return total;
        }

        private static ushort U16(byte[] b, int o) => BitConverter.ToUInt16(b, o);
        private static uint U32(byte[] b, int o) => BitConverter.ToUInt32(b, o);
    }
}
