# swarm-court rubric

The rules qa.py enforces, written down so hunters, skeptics and humans read the same thing.

## Severity

| Severity | Meaning | Examples |
|---|---|---|
| CRITICAL | Data loss or corruption, money or stock wrong, someone sees or does what they must not | double charge, overselling, tenant data leak, auth bypass, IDOR on personal data |
| HIGH | Wrong business outcome, or an unhandled failure users will notice, or a privilege issue | order stuck in the wrong status, job fails with no retry or alert, user can edit a field reserved for admins |
| MEDIUM | Misbehaviour on an edge case, missing validation, a performance risk at scale | 500 on an emoji name, N+1 on a list page, missing index on a filter column |
| LOW | Cosmetic, a minor inconsistency, or a hardening suggestion | wrong error message text, inconsistent date format |

Rate the impact if the trigger happens, not how likely the trigger is. The skeptic's verdict covers likelihood.

## Finding validity (`qa.py validate`)

A finding is rejected, moved to `findings/_rejected/` and given a recorded reason if:

1. it is missing a frontmatter field (`id`, `lane`, `title`, `severity`, `category`, `location`, `root_cause`) or one of the six sections (What breaks, Why, Exact trigger, Expected vs actual, Suggested test, Suggested fix);
2. `severity` is not CRITICAL, HIGH, MEDIUM or LOW;
3. `location` has no `file:line`, or that file does not exist in the repo;
4. "Exact trigger" has fewer than 40 characters, or contains no concrete value, no HTTP verb or route, no sequence ("then", "while", "after") and no timing statement;
5. the title or trigger only hedges ("may", "might", "could potentially", "consider") and gives no concrete trigger;
6. "Suggested test" is empty;
7. it is CRITICAL or HIGH and "Why" contains no `file:line` citation;
8. it is beyond the hunter's first 8 findings. Extras are rejected as `over-cap`, starting with the lowest severity.

If more than 50% of a lane's findings are rejected, one fix-pass hunter is spawned for that lane. This happens once per lane.

## Verdicts (skeptics)

| Verdict | Meaning | Required evidence |
|---|---|---|
| CONFIRMED | Reproduced by a test, or observed directly | a file:line citation, plus the test path and its output |
| LIKELY | The code path clearly allows it, but it was not reproduced | file:line of the unguarded path + what blocked reproduction |
| LATENT | A real defect that is unreachable today only because another bug stops execution first. It goes live when that bug is fixed. Gate: always WARN (never silently passed). Test case: Blocked | file:line of the defect + the masking bug |
| DISPUTED | The code prevents it | file:line of the guard (middleware, policy, constraint, lock, validation rule) |
| NEEDS-ENV | Needs infrastructure the sandbox lacks | file:line + what infrastructure would settle it |
| UNVERIFIED | `--no-verify` was used, so no skeptic ran | (none) |

- A verdict without any `file:line` is rejected. The finding is re-queued once. If the second verdict is also invalid, the finding becomes NEEDS-ENV.
- **Race rule:** a `race-conditions` finding (or any finding with `category: race`) can only be CONFIRMED by a test that uses real parallelism: separate processes or separate DB connections released together by a barrier. Calling an endpoint twice in sequence does not reproduce a race. qa.py checks the evidence rather than trusting the skeptic's word. A race CONFIRMED is downgraded to LIKELY, with the reason recorded, unless all of these hold:
  1. the verdict sets `parallel_test: yes`;
  2. `test:` names a file that exists inside `.swarm-court/<run>/tests/` (a test elsewhere does not count);
  3. that file uses a real parallel construct, such as `Process::pool`, `Concurrency::run`, `pcntl_fork`, `proc_open` or `Http::pool` in PHP; `multiprocessing`, `ThreadPoolExecutor` or `asyncio.gather` in Python; `Promise.all`, `child_process` or `worker_threads` in JS; `Thread.new` or `fork` in Ruby; `go func` or `sync.WaitGroup` in Go.

  This is a strong signal, not proof. A test can contain a parallel construct and still test the wrong thing. A human should read the test before relying on a CONFIRMED race.

Verdict strength, from strongest to weakest: CONFIRMED > LIKELY > LATENT > NEEDS-ENV > UNVERIFIED > DISPUTED.

- **Performance rule:** a `performance` finding (or any finding with `category: perf`) can only be CONFIRMED if the verdict's `measurement:` names a file inside `.swarm-court/<run>/tests/`: a `bench.py` result, captured query counts, EXPLAIN output, or peak memory. Otherwise it is downgraded to LIKELY.

## Performance budgets and measurement

Latency is measured with `bench.py` against the **local** app only. The tool refuses any non-loopback target, never follows redirects, pins `localhost` to the loopback address that is actually listening (avoiding a ~2 s IPv6 fallback per request on Windows), and caps each run at 500 requests, 8 concurrent and 60 s. It is a measurement, not a load test.

If scope.md gives no budgets, these defaults apply:

| Measure | Default budget |
|---|---|
| API endpoint p95 (local, realistic seed) | <= 500 ms |
| Queries per request | <= 10, and constant in the number of rows returned |
| Growth from 1x to 10x data (paginated reads) | flat or sublinear (`bench.py compare` exponent <= 0.7) |
| Exports, imports and jobs | memory roughly constant in row count (streamed with chunk/cursor/lazy) |

Laptop numbers are noisy, so the strongest evidence is **scaling**: the same operation at two data sizes. Superlinear growth (exponent > 1.2) on a request path is at least MEDIUM, and HIGH when the scope's realistic volume puts p95 over the budget.

## Dedupe (`qa.py dedupe`, deterministic)

Two findings describe the same issue if any of these holds:

1. their `root_cause` values are identical after normalising case, whitespace and punctuation;
2. **same spot**: they are in the same file, at most 3 lines apart, and their root causes share at least some significant words (word overlap ≥ 0.10). Category does not matter: different lanes label the same bug `queue`, `integrity` or `perf`;
3. **same function**: they are in the same file, at most 10 lines apart, inside the same function or method (found by scanning upward for the nearest `function` / `def` / `func`; unknown counts as a match), and their root causes clearly overlap (≥ 0.30);
4. **fuzzy title**: they are in the same file and `difflib` gives a similarity of at least 0.75 for title + root_cause.

Findings in **different files** merge only through rule 1. Two IDORs in two controllers read almost the same but need two fixes.

Duplicates reported by different lanes usually cite the same line but often use different categories, while different bugs in one function sit on different lines with unrelated root causes. The design rule is to prefer under-merging: a missed merge shows a duplicate, but a wrong merge hides a bug.

When findings merge, the survivor is the one with the strongest verdict, and after that the highest severity. It takes the highest severity in the group, the union of the lanes that found it (`found_by_lanes`), and a `merged_from` list. If two or more lanes found it independently, it gets the **multi-lane** badge. DISPUTED findings never merge with non-disputed ones, so a skeptic's disproof stays visible in the report.

## Release gate (`qa.py gate`)

Disputed findings are ignored. Every other final finding is checked:

**BLOCK RELEASE** if any finding that is CONFIRMED or LIKELY is
- CRITICAL, in any lane; or
- HIGH, and in `race-conditions`, `authz-security` or `data-integrity` (by lane or category), or about payments, billing, inventory/stock or tenant isolation. The topic check is skipped for `perf`, `ui` and `ops` findings: a slow invoice query is not a billing-correctness bug.

**WARN** if no finding blocks but MEDIUM findings remain, a non-sensitive HIGH is CONFIRMED or LIKELY, or any HIGH or CRITICAL is only NEEDS-ENV or UNVERIFIED.

**PASS** if there are no findings, or only LOW findings.

The gate always lists its reasons and the coverage gaps: lanes that were skipped, checklist items no hunter examined, NEEDS-ENV findings, and hunters that failed to report.

## Test-case status mapping

| Verdict | Test-case status |
|---|---|
| CONFIRMED | Fail |
| LIKELY / LATENT | Blocked |
| NEEDS-ENV / UNVERIFIED | Not tested |
| DISPUTED | Pass |
