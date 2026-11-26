# Service memory leak: DetectionEngine drain loop (fixed in 3.7.8)

Incident record for the `Gnyida.Service` memory growth seen on 3.7.7. Read this before changing the
`DetectionEngine` telemetry drain loop, `DualLaneWait`, or any code that waits on a channel or a
cancellation token from a long-running loop.

Status: **fixed in source and unit-tested; not yet confirmed on a running service.** The acceptance
check is in [Verification](#verification-and-acceptance-criteria). Update this file with the result.

## Summary

| | |
|---|---|
| Symptom | `Gnyida.Service` working set reached 9.9 GB after about two days of uptime. |
| Root cause | `DetectionEngine.ProcessTelemetryQueueAsync` started a new pair of `WaitToReadAsync` calls on every idle pass and raced them with `Task.WhenAny`. The losing wait stayed pending forever. |
| Size of leak | 15.8 million leaked waits, about 4.9 GB of live objects in the 3.7.7 heap dump. |
| Fix | `DualLaneWait` keeps at most one outstanding wait per lane and re-issues a wait only after it completes. |
| Behavior change | None to detection, tiers, deduplication or response. Only the idle wait mechanics changed. |
| Tests | `tests/Gnyida.Tests/DualLaneWaitTests.cs`. Full suite 3,761 passed, 9 skipped, 0 failed. |

## Evidence

### Growth curve (`Logs\diagnostic.jsonl`, `[GnyidaHealthCheck] High memory usage`)

The service started on 15 Nov at about 10:21 and was never restarted. Times are as displayed in local time.

| Time | Reported memory |
|---|---|
| 15 Nov 11:11 | 507 MB (first warning) |
| 15 Nov 12:01 | 959 MB |
| 15 Nov 18:01 | 2,320 MB |
| 15 Nov 22:01 | 4,177 MB |
| 16 Nov 00:01 | 5,140 MB |
| 16 Nov 12:01 | 6,934 MB |
| 16 Nov 22:01 | 8,699 MB |
| 17 Nov 00:01 | 9,097 MB |

Growth was about 500 MB per hour at busy times and about 100 to 250 MB per hour when the machine was quiet.
It never levelled off. The rate followed telemetry volume: `ops_metrics.json` showed 16.8 million telemetry
events and 730 million ETW events processed, with `TelemetryDropped = 0` and an idle pipeline (queue depth 0).
A backlog was therefore not the cause.

### VMMap (managed or native)

| Row | Committed |
|---|---|
| Managed Heap | 9,538 MB |
| Private Data | 187 MB |
| Native Heap | 121 MB |
| Image | 121 MB |
| Stack | 5 MB |

About 97% of the process was the .NET managed heap. Native allocations, COM and WMI objects, certificate
handles, ETW native buffers and thread growth were ruled out in one step.

### Heap dump (ProcDump `-ma`, 9.84 GB; analyzed with ClrMD, see `tools/diagnostics/heap-dump/`)

90,176,780 objects, 9,671 MB.

| MB | Count | Type |
|---|---|---|
| 3,838 | 9,811,444 | Free (unused space in the heap, not retained) |
| 1,686 | 15,789,823 | `System.Threading.Channels.AsyncOperation<bool>` |
| 1,205 | 15,789,826 | `System.Threading.Tasks.Task<bool>` |
| 843 | 15,791,274 | `System.Threading.CancellationCallbackInfo` |
| 602 | 15,794,308 | `System.Collections.Generic.List<object>` |
| 602 | 15,789,815 | `ValueTask<bool>+ValueTaskSourceAsTask` |
| 534 | 2,637 | `System.Int64[]` (unreachable garbage, see below) |

The five leaked types have the same count (about 15.79 million) and total about 4.9 GB, which is 85% of the
non-free heap. Equal counts across a type family mean one allocation per occurrence of some event. The count
is close to the 16.8 million telemetry events processed, which means about one leaked wait per
idle-to-busy transition of the telemetry queues.

Referrer scan: each leaked `AsyncOperation<bool>` is referenced by a `CancellationCallbackInfo` (the
registration on the cancellation token), a `ValueTaskSourceAsTask` and the previous `AsyncOperation<bool>`.
That is the channel's linked waiter list, with every entry also registered on the token.

## Root cause

`DetectionEngine.ProcessTelemetryQueueAsync` is the single drain loop for two lanes, the priority lane and
the normal lane. The 3.7.7 code, when both lanes were empty:

```csharp
var priorityWait = priorityReader.WaitToReadAsync(ct).AsTask();
var normalWait   = normalReader.WaitToReadAsync(ct).AsTask();
var ready = await Task.WhenAny(priorityWait, normalWait);
```

`Task.WhenAny` returns when the first wait completes, but it does not cancel the other. Almost every wake-up
was a normal-lane item, so the priority wait was left pending. A pending `WaitToReadAsync` on a channel:

1. is queued in the channel's list of waiting readers until that lane next receives data, and
2. holds a registration on the cancellation token it was given (`ct` is `_cts.Token`, which lives for the
   whole service lifetime).

The priority lane (terminal-class telemetry) is written rarely, so these waits were not completed. Every
idle pass added one more. They were reachable from the channel and from the token, so the GC could never
free them. This is a leak of pending asynchronous operations, not a large cache.

## Why earlier fixes did not help

- 3.7.3 capped `SignerTrustService`, `MappedModuleCache` and `DllUnloadEngine` per-PID sets after a code
  review. Those caps are sound hygiene, but none of those structures was the leak. That fix was made without
  a heap dump (the 3.7.3 changelog entry says so).
- Earlier history (0.4.2, 0.4.4, 0.4.7, 1.5.4, 2.4.7, 3.2.1, 3.6.3) was also unbounded caches or feedback
  loops. This was the first leak caused by pending async waits, so a search for unbounded dictionaries and
  queues could not find it. A static scan of every collection field in `src/` found nothing unbounded that
  was keyed on event data.
- The lesson is in `tools/diagnostics/heap-dump/README.md`: take VMMap and a dump first, then read code.

## Fix

- New `src/Gnyida.Core/DualLaneWait.cs` (internal). It holds one outstanding `WaitToReadAsync` per lane and
  re-issues a wait only after it has completed. `WaitAsync` returns the wait that completed, which is then
  consumed.
- `DetectionEngine.ProcessTelemetryQueueAsync` creates one `DualLaneWait` before the loop and calls
  `lanes.WaitAsync(ct)` where the two inline waits used to be. The priority-first drain order, the
  one-normal-item-per-pass rule and the completion/exit check are unchanged.
- With the fix there are at most two pending waits for the life of the service.

## What was checked and ruled out

These are recorded so nobody repeats the search.

| Suspect | Result |
|---|---|
| `TelemetryFusionEngine` chains | Bounded: 500 events per PID, 8,000 PIDs, pruned every 15 s with 2-minute retention. |
| `EventGraph` | Bounded: 300 edges per process, hard caps of 5,000, 10,000 and 3,000 nodes, pruned every 15 s. |
| `ContextBus`, `FileScanIndex`, `ProcessAncestryCache`, `CredentialReadTracker` | Bounded or pruned. |
| PID-keyed dictionaries (`_pidToIncident`, `_lastEmit`, `_spawnCounts`, ...) | Small: bounded by distinct PIDs. |
| Native allocations (`AllocHGlobal`, certificates, `WinVerifyTrust` state) | Not the cause: native heap and Private Data total about 300 MB. |
| Scanning of RAM | There is no periodic RAM scan. `MemoryBehaviorAnalyzer` does one baseline pass at startup. Module checks run per ETW image-load in `DllUnloadEngine` and hold a few MB. `MemoryAnomalyScanner` runs only from the dashboard on demand. |
| `Int64[]`, 534 MB | Only 2 of 2,637 arrays are rooted (0.3 MB). The rest has no referrer and is not a root, so it is unreachable garbage awaiting a collection. |
| `BoundedEtwDispatcher` queue segments (271,226) | Dead chains. `ConcurrentQueue` segments link forward; the four oldest segments have no holder, and the four live queues (one per dispatch lane) hold only their current segment. Not a leak. |

Two conclusions in the working notes were wrong and were corrected during the investigation: the segment
chain was first read as "something retains an old segment", and the `Int64[]` was first read as "no
referrers" without checking roots. Both are covered by the rules in the README of the heap tools.

### Other racing-wait sites (audited, not changed)

Every `Task.WhenAny` / `Task.WaitAny` in `src/` was reviewed for the same pattern.

| Site | Verdict |
|---|---|
| `BoundedIpcRequest.ReadAsync` | Per-call linked token source, disposed (`using`). Safe. |
| `BoundedIpcRequest.WithinDeadlineAsync` | Races against `Task.Delay(Infinite, ct)`. Safe because all three callers (`ServiceAgentIpc` x2, `PrivacyOverlayProofInspector`) pass a per-call `deadline.Token`. Would leak if a caller passed a service-lifetime token. |
| `DashboardSocketClients.SendAsync` | Per-call linked token source, disposed. Safe. |
| `LanDeviceInventoryMonitor.RunArpAsync` | `Task.Delay(10 s, ct)`: completes by itself within 10 s. Safe. |
| `WindowsFirewallPolicyBridge` | Per-call linked token source, disposed. Safe. |
| `ContextBus` | `while (await reader.WaitToReadAsync(token))`: one outstanding wait at a time. Safe. |

## Rules for future changes (do not regress)

1. **Never start a new `WaitToReadAsync`, `Task.Delay(..., token)`, `token.Register(...)` or similar on a
   long-lived token inside a loop and then abandon it.** An abandoned wait stays registered on the token and
   in the owner's waiter list until it completes. If you race two waits, either reuse the pending wait
   (use `DualLaneWait`) or give the race its own linked `CancellationTokenSource`, cancel it when the race
   is decided, and dispose it.
2. **Adding a third lane** to the drain loop: extend `DualLaneWait` (or a sibling) and its tests. Do not
   reintroduce an inline `Task.WhenAny` over fresh waits.
3. **Keep `DualLaneWaitTests`.** `IdleLane_IsNotReWaited_WhenOtherLaneKeepsWaking` is the regression guard:
   after 500 idle-to-busy cycles the never-written lane must have been waited on exactly once. If it ever
   reports 500, the leak is back.
4. A per-call helper that takes a `CancellationToken` and races it must be called with a per-call token.
   `WithinDeadlineAsync` documents this above; do not pass a service-lifetime token.
5. When a "memory fix" is proposed without a heap dump, treat it as unproven. Record the dump evidence in
   the changelog, as this file does.

## Verification and acceptance criteria

Automated (done, on the build that contains the fix):

- `DualLaneWaitTests`: one wait per lane reused across 500 cycles; a completed wait is re-issued; a
  cancelled wait is reported as cancelled; completed channels report no more data.
- Pipeline tests (`IntegrationPipelineTests`, `FastLaneTests`, `DetectionEngineTests`) plus the new `DualLaneWaitTests`: 33 of 33 passed.
- Full suite with `-warnaserror`: 3,761 passed, 9 skipped, 0 failed.

On a running service (**pending**, requires installing 3.7.8):

- After 24 hours of uptime, `Gnyida.Service` working set should stay in the hundreds of MB, and
  `[GnyidaHealthCheck] High memory usage` should not appear. Before the fix it grew by 100 to 600 MB per
  hour.
- If it still grows, do not guess. Follow `tools/diagnostics/heap-dump/README.md`: VMMap first, then a dump,
  then `HeapTypeStats`. Compare the top non-Free types against the table above.
- Record the result here when known.

The unit tests prove the wait behavior. They cannot prove the production memory curve, which is why the
running-service check is listed separately.

## Files

| File | Change |
|---|---|
| `src/Gnyida.Core/DualLaneWait.cs` | New. One outstanding wait per lane. |
| `src/Gnyida.Core/DetectionEngine.cs` | Drain loop uses `DualLaneWait`. |
| `tests/Gnyida.Tests/DualLaneWaitTests.cs` | New. Four regression tests. |
| `tools/diagnostics/heap-dump/` | New. Analyzer sources and procedure (not part of the solution). |
| `docs/design.md`, `docs/CHANGELOG.md` | Updated. |
