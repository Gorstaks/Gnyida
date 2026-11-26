using System;
using System.IO;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    public class ImageIntegrityVerifierTests
    {
        private static readonly string Sample = Path.Combine(Environment.SystemDirectory, "ping.exe");

        /// <summary>Lays a PE file out as the loader would at its preferred base (no relocation applied).</summary>
        private static byte[] MapImage(byte[] file, out uint entryPoint, out uint textRva, out int peOffset)
        {
            peOffset = BitConverter.ToInt32(file, 0x3C);
            int sections = BitConverter.ToUInt16(file, peOffset + 6);
            int optSize = BitConverter.ToUInt16(file, peOffset + 20);
            int opt = peOffset + 24;
            entryPoint = BitConverter.ToUInt32(file, opt + 16);
            uint sizeOfImage = BitConverter.ToUInt32(file, opt + 56);
            uint sizeOfHeaders = BitConverter.ToUInt32(file, opt + 60);
            var image = new byte[sizeOfImage];
            Array.Copy(file, 0, image, 0, Math.Min(sizeOfHeaders, (uint)file.Length));
            textRva = 0;
            for (int i = 0; i < sections; i++)
            {
                int o = opt + optSize + i * 40;
                uint virtualAddress = BitConverter.ToUInt32(file, o + 12);
                uint rawSize = BitConverter.ToUInt32(file, o + 16);
                uint rawPointer = BitConverter.ToUInt32(file, o + 20);
                uint characteristics = BitConverter.ToUInt32(file, o + 36);
                if (rawPointer != 0) Array.Copy(file, rawPointer, image, virtualAddress, Math.Min(rawSize, (uint)(file.Length - rawPointer)));
                if (textRva == 0 && (characteristics & 0x20000000) != 0) textRva = virtualAddress;
            }
            return image;
        }

        private static ImageIntegrityVerifier.Result Run(byte[] file, byte[] image) =>
            ImageIntegrityVerifier.Compare(new MemoryStream(file), (rva, buffer, count) =>
            {
                if (rva + (long)count > image.Length) return false;
                Array.Copy(image, rva, buffer, 0, count);
                return true;
            });

        private static bool HaveSample() => File.Exists(Sample);

        [Fact]
        public void FaithfulImage_IsClean()
        {
            if (!HaveSample()) return;
            byte[] file = File.ReadAllBytes(Sample);
            byte[] image = MapImage(file, out _, out _, out _);
            var result = Run(file, image);
            Assert.True(result.Comparable, result.Reason);
            Assert.Equal(0, result.DifferingBytes);
            Assert.Equal(ImageIntegrityVerifier.Verdict.Clean, ImageIntegrityVerifier.Classify(result));
        }

        [Fact]
        public void ReplacedCode_IsReported()
        {
            if (!HaveSample()) return;
            byte[] file = File.ReadAllBytes(Sample);
            byte[] image = MapImage(file, out _, out uint text, out _);
            for (int i = 0; i < 4096; i++) image[text + 64 + i] = (byte)(0xA5 ^ i);
            Assert.Equal(ImageIntegrityVerifier.Verdict.CodeReplaced, ImageIntegrityVerifier.Classify(Run(file, image)));
        }

        [Fact]
        public void PatchedEntryPoint_IsReported()
        {
            if (!HaveSample()) return;
            byte[] file = File.ReadAllBytes(Sample);
            byte[] image = MapImage(file, out uint entry, out _, out _);
            for (int i = 0; i < 16; i++) image[entry + i] ^= 0xFF;
            Assert.Equal(ImageIntegrityVerifier.Verdict.EntryPointPatched, ImageIntegrityVerifier.Classify(Run(file, image)));
        }

        [Fact]
        public void HookSizedPatch_IsNotReported()
        {
            if (!HaveSample()) return;
            byte[] file = File.ReadAllBytes(Sample);
            byte[] image = MapImage(file, out _, out uint text, out _);
            // A 14-byte trampoline (mov rax, imm64; jmp rax) as left by Detours or an overlay.
            for (int i = 0; i < 14; i++) image[text + 0x200 + i] ^= 0xFF;
            var result = Run(file, image);
            Assert.True(result.DifferingBytes > 0);
            Assert.Equal(0, result.DenseBlocks);
            Assert.Equal(ImageIntegrityVerifier.Verdict.Clean, ImageIntegrityVerifier.Classify(result));
        }

        [Fact]
        public void PayloadSizedPatch_IsReportedEvenWhenSmallRelativeToTheModule()
        {
            if (!HaveSample()) return;
            byte[] file = File.ReadAllBytes(Sample);
            byte[] image = MapImage(file, out _, out uint text, out _);
            // 600 pseudo-random bytes: well below the 4 KB run limit and the 10% share, caught by block density.
            var rnd = new Random(7);
            for (int i = 0; i < 600; i++) image[text + 0x400 + i] = (byte)rnd.Next(256);
            var result = Run(file, image);
            Assert.True(result.LongestDifferingRun < ImageIntegrityVerifier.ReplacedRunBytes);
            Assert.True(result.DifferingBytes * 100 < result.ComparedBytes * ImageIntegrityVerifier.ReplacedPercent);
            Assert.True(result.DenseBlocks >= ImageIntegrityVerifier.DenseBlocksReplaced, "dense blocks: " + result.DenseBlocks);
            Assert.Equal(ImageIntegrityVerifier.Verdict.CodeReplaced, ImageIntegrityVerifier.Classify(result));
        }

        [Fact]
        public void ChangedHeader_IsReported()
        {
            if (!HaveSample()) return;
            byte[] file = File.ReadAllBytes(Sample);
            byte[] image = MapImage(file, out _, out _, out int pe);
            image[pe + 8] ^= 0xFF; // TimeDateStamp: a different image than the file the process claims
            var result = Run(file, image);
            Assert.True(result.HeaderMismatch);
            Assert.Equal(ImageIntegrityVerifier.Verdict.HeaderMismatch, ImageIntegrityVerifier.Classify(result));
        }

        [Fact]
        public void UnreadableMemory_IsIncomparableNotClean()
        {
            if (!HaveSample()) return;
            byte[] file = File.ReadAllBytes(Sample);
            byte[] image = MapImage(file, out _, out uint text, out _);
            var result = ImageIntegrityVerifier.Compare(new MemoryStream(file), (rva, buffer, count) =>
            {
                if (rva >= text) return false; // headers readable, code pages not
                Array.Copy(image, rva, buffer, 0, count);
                return true;
            });
            Assert.NotEqual(ImageIntegrityVerifier.Verdict.Clean, ImageIntegrityVerifier.Classify(result));
            Assert.Equal(ImageIntegrityVerifier.Verdict.Incomparable, ImageIntegrityVerifier.Classify(result));
        }

        [Fact]
        public void NonPeFile_IsIncomparable()
        {
            var result = ImageIntegrityVerifier.Compare(new MemoryStream(new byte[2048]), (rva, buffer, count) => true);
            Assert.False(result.Comparable);
            Assert.Equal(ImageIntegrityVerifier.Verdict.Incomparable, ImageIntegrityVerifier.Classify(result));
        }

        [Fact]
        public void TruncatedFile_IsIncomparableNotAnException()
        {
            if (!HaveSample()) return;
            byte[] file = File.ReadAllBytes(Sample);
            byte[] image = MapImage(file, out _, out _, out _);
            byte[] truncated = new byte[2048];
            Array.Copy(file, truncated, truncated.Length);
            var result = Run(truncated, image);
            Assert.Equal(ImageIntegrityVerifier.Verdict.Incomparable, ImageIntegrityVerifier.Classify(result));
        }

        [Fact]
        public void Classify_SmallScatteredDifferences_StayClean()
        {
            var r = new ImageIntegrityVerifier.Result
            {
                Comparable = true, ComparedBytes = 1_000_000, DifferingBytes = 40, LongestDifferingRun = 5,
                TotalPages = 250,
            };
            Assert.Equal(ImageIntegrityVerifier.Verdict.Clean, ImageIntegrityVerifier.Classify(r));
        }

        [Theory]
        [InlineData(4096, 1_000_000, 0, true)]        // one long run
        [InlineData(300, 1_000_000, 100_000, true)]   // 10% of bytes
        [InlineData(300, 1_000_000, 99_999, false)]
        public void Classify_Thresholds(int run, long compared, long differing, bool expectReplaced)
        {
            var r = new ImageIntegrityVerifier.Result
            {
                Comparable = true, ComparedBytes = compared, DifferingBytes = differing, LongestDifferingRun = run, TotalPages = 250,
            };
            Assert.Equal(expectReplaced, ImageIntegrityVerifier.Classify(r) == ImageIntegrityVerifier.Verdict.CodeReplaced);
        }

        [Fact]
        public void Classify_MostlyUnreadable_IsIncomparable()
        {
            var r = new ImageIntegrityVerifier.Result
            {
                Comparable = true, ComparedBytes = 8192, DifferingBytes = 0, TotalPages = 10, UnreadablePages = 6,
            };
            Assert.Equal(ImageIntegrityVerifier.Verdict.Incomparable, ImageIntegrityVerifier.Classify(r));
        }
    }
}
