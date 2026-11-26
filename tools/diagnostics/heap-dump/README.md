# Heap dump diagnosis for Gnyida.Service

How the 3.7.7 memory leak was found (full write-up: [`docs/MEMORY_LEAK_3.7.8.md`](../../../docs/MEMORY_LEAK_3.7.8.md)).
Use this when `[GnyidaHealthCheck] High memory usage` appears in `%ProgramData%\Gnyida\Logs\diagnostic.jsonl`
and the number keeps climbing.

## 1. Decide managed versus native (about one minute)

Run Sysinternals **VMMap** elevated and select `Gnyida.Service`. Compare these rows:

| Row | Meaning |
|---|---|
| Managed Heap | .NET objects. If this is nearly all of the committed size, it is an object leak. |
| Heap, Private Data | Native allocations (`AllocHGlobal`, COM, WMI, ETW buffers). |
| Stack | Thread stacks. |

In 3.7.7: Managed Heap 9,538 MB of about 9,980 MB committed. Native heap 121 MB, Private Data 187 MB.

## 2. Take a dump (elevated; the service runs as SYSTEM)

```
mkdir C:\Temp
procdump64 -accepteula -ma <ServicePid> C:\Temp\gnyida.dmp
```

The dump is about the size of the working set, and the service pauses for a few seconds. **Do not restart
the service first**; a restart clears the leak. The dump contains the service's memory, which can include
scanned data, paths and tokens. Treat it as sensitive and delete it when finished.

## 3. Analyze with ClrMD

The sources are `.cs.txt` so that no project in the repository builds them. Create a scratch project outside
the repository:

```
dotnet new console -n An
cd An
dotnet add package Microsoft.Diagnostics.Runtime
copy <repo>\tools\diagnostics\heap-dump\HeapTypeStats.cs.txt Program.cs
dotnet run -c Release -- C:\Temp\gnyida.dmp 30
```

`HeapTypeStats` prints the heap by type (size and count). A healthy service has a small heap dominated by
strings, byte arrays and the bounded caches. A leak shows as one type family with a very large and growing
count. Ignore the `Free` row: it is unused space inside the heap, not retained objects.

Then swap in `HeapReferrers.cs.txt` as `Program.cs` and run it on the suspect type to see what holds it:

```
dotnet run -c Release -- C:\Temp\gnyida.dmp "System.Threading.Channels.AsyncOperation<System.Boolean>" 5
```

If output is truncated or the run exits with -1 when piped through `Select -First` or similar, redirect
standard output to a file instead; the tools themselves exit 0.

Both tools were written against ClrMD 3.x and a .NET 11 SDK, reading a .NET Framework 4.8 dump on the same
machine (ClrMD finds the matching DAC locally). Walking 90 million objects took about 35 seconds for the type
summary and about two minutes for the referrer scan.

## 4. Rules of thumb learned

- Count objects, do not just read sizes. 15.8 million equal counts across five types in one family is a
  per-event or per-iteration allocation that is never released.
- "No referrers" is not a leak. If an object has no heap referrer and is not a direct root, the GC will
  collect it. Check roots before reporting it.
- Segments or nodes of a linked structure point forward. An old head with no holder means the whole chain
  behind it is dead.
