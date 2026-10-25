# Swarm Court

**A QA team of sub-agents for Claude Code.** Run `/swarm-court` on a feature, page, endpoint, PR, diff or module. Specialist sub-agents each hunt a different class of bug, **backend and frontend**: functional, race conditions, data integrity, authorization/security, database, queue/cache/external services, performance, frontend (Vue/React/Inertia/Livewire/Blade), UI/UX, ops, and a hostile "adversary". A separate **skeptic** agent then tries to disprove every finding. You get one deduplicated, severity-ranked report with reproducible test cases and a release gate verdict: **PASS / WARN / BLOCK**.

- Free, MIT licensed. No API key, no signup.
- `qa.py` is Python 3.8+ standard library only. Nothing to `pip install`.
- Laravel-first (PHP, Pest/PHPUnit, MySQL/Postgres, Redis queues). It detects Node, Django/FastAPI/Flask, Rails and Go from `package.json` / `pyproject.toml` / `Gemfile` / `go.mod` and translates the techniques for that stack. It also detects the frontend (Inertia, Livewire, Blade, Vue, React, Svelte, Alpine, Next/Nuxt) along with its test runner (Vitest/Jest, Playwright/Cypress), and notes whether `node_modules` is installed.

## Install

**Option 1: paste the URL into Claude Code**

> Install the Claude Code skill from https://github.com/Ashvii/swarm-court into ~/.claude/skills/swarm-court

**Option 2: git clone + copy**

```bash
git clone https://github.com/Ashvii/swarm-court.git
mkdir -p ~/.claude/skills
cp -r swarm-court/skills/swarm-court ~/.claude/skills/swarm-court      # personal, all projects
# or, per project:  cp -r swarm-court/skills/swarm-court .claude/skills/swarm-court
```

**Option 3: plugin**

```
/plugin marketplace add Ashvii/swarm-court
/plugin install swarm-court@swarm-court
```

(As a plugin, the command is namespaced: `/swarm-court:swarm-court`.)

Recommended: switch to accept-edits mode (Shift+Tab) before a run, because every agent writes files under `.swarm-court/`.

## Usage

```
/swarm-court                                  # scope = what you just asked about, or your uncommitted diff
/swarm-court the checkout endpoint            # explicit target
/swarm-court --diff main                      # everything changed vs main
/swarm-court --quick                          # 5 core lanes (+ frontend if the project has one), depth 1 (~30 calls)
/swarm-court --lanes race,authz app/Jobs/     # only these lanes
/swarm-court --lanes fe,ui the download page    # frontend-only review
/swarm-court --skip ui-ux,perf                # everything except these
/swarm-court --depth 3                        # 3 hunters per lane, each from a different angle
/swarm-court --no-verify                      # skip skeptics: cheaper, noisier, everything UNVERIFIED
/swarm-court --wave 5                         # at most 5 parallel sub-agents
/swarm-court --seed 42                        # reproducible angle dealing
/swarm-court --rerun race                     # after a fix: re-run only the race lane on the same scope
```

Or just ask: *"is this production ready?"*, *"break this"*, *"find bugs in the refund flow"*. When Claude triggers the skill itself, it shows the cost plan and asks before spending.

## Example report

From a two-lane run (`--lanes race,authz --depth 1`) on a small sample checkout API. Abridged; see the full [`sample-report.md`](examples/sample-report.md) and [`sample-testcases.csv`](examples/sample-testcases.csv).

> ## Release gate: BLOCK
>
> - BLOCK: RC-001 CRITICAL CONFIRMED: Overselling the last unit under concurrent checkout
> - BLOCK: AZ-001 HIGH CONFIRMED: Any user can read any other user's order (IDOR) (HIGH in a sensitive area: lane authz-security)
>
> | ID | Severity | Lane(s) | Title | Verdict | Location |
> |---|---|---|---|---|---|
> | RC-001 | CRITICAL | race-conditions | Overselling the last unit under concurrent checkout | CONFIRMED | `app/Http/Controllers/OrderController.php:16` |
> | AZ-001 | HIGH | authz-security | Any user can read any other user's order (IDOR) | CONFIRMED | `app/Http/Controllers/OrderController.php:21` |
> | AZ-002 | HIGH | authz-security | Guests can place orders without logging in | DISPUTED | `app/Http/Controllers/OrderController.php:10` |
>
> #### RC-001 · CRITICAL · Overselling the last unit under concurrent checkout
>
> **What breaks.** Two buyers both get an order for the last unit, and stock goes negative.
>
> **Exact trigger.** Product 7 has stock = 1. Two clients POST /api/checkout {"product_id":7,"quantity":1} at the same time.
>
> **Failing test** (written by the skeptic: `.swarm-court/20261025-113529-checkout/tests/CheckoutRaceTest.php`)
>
> ```php
> it('sells the last unit only once', function () {
>     $product = Product::factory()->create(['stock' => 1]);
>     $results = Process::pool(fn ($pool) => [
>         $pool->command("php artisan test:checkout {$product->id}"),
>         $pool->command("php artisan test:checkout {$product->id}"),
>     ])->start()->wait();
>     expect(Order::count())->toBe(1)->and($product->fresh()->stock)->toBe(0);
> });
> ```
>
> **Suggested fix.** Replace the read-then-save with an atomic guarded update: `Product::whereKey($id)->where('stock', '>=', $q)->decrement('stock', $q)` and return 422 when it affects 0 rows.
>
> ## Disputed (skeptics disproved these)
>
> - **AZ-002** HIGH · Guests can place orders without logging in · `app/Http/Controllers/OrderController.php:10`
>   - Skeptic's evidence: routes/api.php:3 wraps POST /checkout in middleware('auth:sanctum'), which returns 401 before the controller runs.

## How it works

```
 you: /swarm-court checkout
   │
   ▼
 SCOPE ─────── orchestrator reads routes, controllers, models, policies, migrations, jobs, tests
   │           writes .swarm-court/<run>/scope.md  (the ONLY context agents get; SHA-256 recorded)
   ▼
 PLAN ──────── qa.py plan → cost table; asks first if auto-triggered or > 60 calls
   ▼
 HUNT ──────── lanes × depth hunters, in waves of 10        ┌ functional        ┌ angle 1 code-reading
   │           each writes findings/*.md + a .done marker   ├ race-conditions   ├ angle 2 test-first
   │           and replies with ONE line                    ├ data-integrity    ├ angle 3 data-driven
   │                                                        ├ authz-security    ├ angle 4 attacker
   │                                                        ├ database          └ angle 5 historical
   │                                                        ├ queue-cache-external
   │                                                        ├ performance · frontend · ui-ux
   │                                                        ├ chaos-ops
   │                                                        └ adversary
   ▼
 VALIDATE ──── pure Python: rejects vague or malformed findings (no file:line, hedging, no trigger,
   │           no test, over the 8-per-hunter cap). >50% of a lane rejected → one fix-pass hunter
   ▼
 VERIFY ────── one skeptic per finding. Sees scope + claim only, never the hunter's reasoning.
   │           CONFIRMED / LIKELY / DISPUTED / NEEDS-ENV, each with file:line evidence.
   │           Race claims need a real parallel test file (checked by qa.py) to be CONFIRMED.
   ▼
 DEDUPE ────── pure Python: same root cause / same function ±10 lines / fuzzy title → merge,
   │           keep the best evidence + highest severity, mark "multi-lane"
   ▼
 REPORT ────── REPORT.md + testcases.csv + release gate (PASS / WARN / BLOCK)
```

A thin orchestrator prompt drives a standard-library Python state machine. Sub-agents write to disk and reply with one line, so the main conversation stays small even with 100 agents. The orchestrator never opens a finding or verdict file; only `qa.py` reads them. Every step is recorded in `.swarm-court/<run>/state.json` with atomic writes. If the conversation is compacted or interrupted, `qa.py next` says exactly what to do next.

## Lanes

| Lane | Hunts for | Skipped when |
|---|---|---|
| `functional` | business rules, validation, boundaries, state transitions, error responses | never |
| `race-conditions` | lost updates, double processing, overselling, duplicate callbacks; must prove with real parallelism | no shared mutable state |
| `data-integrity` | orphans, partial writes, money as floats, timezones, side effects before commit, soft deletes | no writes |
| `authz-security` | 401/403, IDOR, tenant isolation, mass assignment, leaks, injection, XSS, rate limits | never for reachable code |
| `database` | missing constraints/indexes, N+1, migrations on populated tables, deadlock/retry safety | no DB access |
| `queue-cache-external` | retries, duplicate side effects, failed_jobs, Redis down, stale cache, webhooks, 429s | no async/integration |
| `performance` | latency measured locally with `bench.py` (p50/p95/p99 against budgets, scaling at 1x vs 10x data), query counts, EXPLAIN, memory in exports/jobs, N+1, unbounded queries, frontend request/poll cost. Never a load test | trivial changes |
| `frontend` | API-contract mismatches (fields/pagination the UI reads but the API never returns), stale-response races, double submit, swallowed errors, client-only authorization, XSS sinks (`v-html`, `{!! !!}`), Livewire property tampering, Inertia shared-prop leaks, leaked pollers | no browser code |
| `ui-ux` | loading/empty/error states, form errors per field, back button, session expiry, a11y, timezones | no UI |
| `chaos-ops` | env/secrets, debug mode, deploy order, `queue:restart`, logging, alerts, rollback | pure refactor |
| `adversary` | replay, reorder, stale tabs, direct API calls, absurd sizes, account switching | never |

Lane cards live in [`skills/swarm-court/lanes.json`](skills/swarm-court/lanes.json) and are meant to be edited. You can add checklist items, add a lane, or change `default_depth`.

## Cost

Numbers from `qa.py plan`, assuming about 5 valid findings per hunter (`--est-findings` changes the estimate). "Calls" means sub-agent invocations.

| Run | Lanes × depth | Hunters | Skeptics (est.) | Calls | Waves of 10 | Asks first? |
|---|---|---|---|---|---|---|
| `--quick --no-verify` | 5 × 1 | 5 | 0 | **5** | 1 | no |
| `--quick` | 5 × 1 | 5 | 25 | **30** | 4 | no |
| `--quick` on a project with a frontend | 6 × 1 | 6 | 30 | **36** | 4 | no |
| default, API-only (`--skip frontend,ui-ux`) | 9 × 2 | 18 | 90 | **108** | 11 | yes (> 60) |
| full (all 11 lanes) | 11 × 2 | 22 | 110 | **132** | 14 | yes |
| full `--depth 3` | 11 × 3 | 33 | 165 | **198** | 21 | yes |

Example: a 7-lane, depth-1 run on a multi-tenant CSV-export feature used **42 calls**: 7 hunters, then 35 skeptics for 35 findings, which deduped to 13 unique bugs. Retries (fix passes and re-queued verdicts) are bounded; `plan` prints the upper bound.

## Output

Everything goes in `.swarm-court/<YYYYMMDD-HHMMSS-slug>/` in your project. The folder ignores itself in git.

| Path | What |
|---|---|
| `REPORT.md` | header, release gate + reasons, summary table, findings by severity (trigger, evidence, failing test, fix, which lanes), disputed findings with the evidence that killed them, needs-env items, coverage matrix, test-case table |
| `testcases.csv` | `Test Case ID, Feature, Scenario, Preconditions, Test data, Steps, Expected result, Actual result, Priority/Severity, Status`, ready for Jira / TestRail / Sheets import. CONFIRMED → Fail, LIKELY → Blocked, NEEDS-ENV → Not tested, DISPUTED → Pass |
| `tests/` | tests and `bench.py` measurements written by hunters and skeptics. They are never copied into your suite unless you say so |
| `scope.md`, `state.json` | the exact context agents saw (with its SHA-256) and the run's state |
| `findings/`, `verdicts/`, `briefs/` | raw agent output (rejects in `_rejected/` with a reason) and the exact brief each agent got |

## Safety

These hard rules are repeated in the skill and in every sub-agent brief:

1. Never edit application source, config, migrations or existing tests. Agents write only inside `.swarm-court/`. Applying generated tests is your decision, and the skill asks first.
2. Nothing that writes data runs unless `APP_ENV` is local/testing **and** the DB name is clearly a test database. Otherwise agents do static analysis only.
3. No load or stress testing. Latency is measured only with `bench.py` against **localhost**: it refuses remote targets, never follows redirects, and caps each run at 500 requests, 8 concurrent and 60 s. No calls to real external services or payment APIs: agents use fakes (`Http::fake`, `Queue::fake`, `Event::fake`) or stop at LIKELY.
4. No exploit tooling, and no scanning outside the local test app.
5. No destructive commands (`migrate:fresh` on a non-test DB, `rm -rf`, `DROP`, …).
6. `.env` values never appear in findings, logs or the report.

## Development

```bash
python3 skills/swarm-court/qa.py plan --quick     # cost table
python3 skills/swarm-court/qa.py detect           # detected backend and frontend stack
python3 skills/swarm-court/bench.py --help        # the local latency tool agents use
```

`qa.py` and `bench.py` use only the Python 3.8+ standard library. `SKILL.md` quotes the hunter and skeptic briefs from `qa.py` word for word, so keep the two in sync when you edit either.

The release gate, the severity definitions and the validation rules are in [`skills/swarm-court/rubric.md`](skills/swarm-court/rubric.md).

## Fine print

- The agents are the same model looking through different lenses. Lanes and angles diversify the search, but they share blind spots.
- A verdict is evidence, not proof. CONFIRMED means a test or observation backed it up. LIKELY means the code path allows it.
- **Skeptics can be wrong.** A DISPUTED finding is shown with the guard the skeptic cited, so you can check the skeptic too.
- A vague scope produces vague findings. The scope.md the orchestrator writes is the biggest single factor in quality.
- It does not replace a real load test, a penetration test, or human exploratory testing.

## License

MIT. See [LICENSE](LICENSE).
