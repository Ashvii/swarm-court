---
name: swarm-court
description: Swarm Court: multi-agent QA. Specialist sub-agents (functional, race conditions, data integrity, authz/security, database, queue/cache/external, performance, frontend, UI/UX, ops, adversary) hunt for backend AND frontend bugs in a feature, page, endpoint, PR, diff or module. A separate skeptic agent tries to disprove each finding, and the run ends in one deduplicated, severity-ranked report with reproducible test cases and a release gate (PASS/WARN/BLOCK). Use when the user asks to QA, test, harden, or review something for bugs, check race conditions or edge cases, or says "break this", "find bugs in this", or "is this production ready". When triggered automatically rather than by /swarm-court, show the cost plan and ask before spending.
argument-hint: "[target] [--quick] [--lanes a,b] [--skip a,b] [--depth N] [--diff BRANCH] [--no-verify] [--wave W] [--seed S] [--rerun LANE]"
disable-model-invocation: false
---

# swarm-court

You are the **orchestrator**. You scope the work, get consent, and relay what `qa.py` tells you. Sub-agents do the hunting and verifying: they write to disk and reply with one line each. `qa.py` (standard library only) does all of the parsing, validation, dedupe, gating and reporting. That split keeps your context small, so a run with 100 agents fits.

Pipeline: **SCOPE → PLAN + CONSENT → HUNT → VALIDATE → VERIFY → DEDUPE → REPORT**

Arguments: `$ARGUMENTS`

## Setup

- `QA` below means `python3 "<this skill's base directory>/qa.py"`. The base directory is printed when this skill loads. On Windows use `python` if `python3` is not on PATH. Run every command from the **project root**: `qa.py` creates `.swarm-court/` there.
- Recommend accept-edits mode (Shift+Tab) before spawning, because every agent writes files under `.swarm-court/`.
- Spawn at most `--wave` Agent calls in one message (default 10). Claude Code also caps parallel tool calls with `CLAUDE_CODE_MAX_TOOL_USE_CONCURRENCY`, so a bigger wave just queues.

## Orchestrator rules (do not break these)

1. **Never open finding or verdict files** (`.swarm-court/<run>/findings/**`, `verdicts/**`) and never open the briefs. Run `QA status`, `QA next` and `QA report`, and trust their output.
2. Each Agent call uses exactly the `description` and `prompt` that `QA next` prints, with `subagent_type: general-purpose`. Do not add context: `scope.md` is the agents' only context, and it must reach every one of them byte for byte.
3. Do not summarise or analyse agent replies. Each one is one line. When a wave returns, run `QA next`.
4. Never edit application code, config, migrations or existing tests, and never apply generated tests without asking. The user decides.
5. If the conversation was compacted or interrupted, run `QA next`. It rebuilds the next step from `state.json`.

## Safety rules (hard requirements; also embedded in every brief)

1. Never edit application source, config, migrations, or existing tests. Write only inside `.swarm-court/`. Generated tests stay there; applying them is the user's decision, and you ask first.
2. Never run anything that writes data unless APP_ENV is local/testing AND the DB name clearly indicates a test database. If unsure, static analysis only.
3. No load/stress testing. Latency is measured ONLY with `bench.py` against the local app: it refuses any non-localhost target, never follows redirects, and caps each run at 500 requests, 8 concurrent and 60 s. No calls to real external services or payment APIs: use fakes (`Http::fake`, `Queue::fake`, `Event::fake`) or stop at LIKELY.
4. No exploit tooling, and no scanning of anything outside the local test app.
5. No destructive commands (`migrate:fresh` on a non-test DB, `rm -rf`, `DROP`, etc.).
6. Secrets: never print `.env` values into findings, logs, scope.md or the report.
7. Never install or update dependencies (npm/yarn/pnpm/composer/pip). Use only tooling already present. Dev servers and browsers: localhost only.

## Step 0: SCOPE

1. **Find the target**, in this order of precedence: (a) text after the command; (b) `--diff <branch>`, meaning `git diff <branch>...HEAD` plus `git diff` for uncommitted work; (c) the user's last request in the conversation; (d) the current uncommitted `git diff`. If none of these gives a testable target, ask **exactly one** clarifying question, then proceed.
2. **Detect the stack**: run `QA detect`. The default assumption is Laravel (PHP, Pest/PHPUnit, MySQL/Postgres, Redis queues). If the project is something else, write scope.md in that stack's terms and give its exact test commands. The briefs tell agents to translate the Laravel techniques.
3. **Read the relevant code yourself.** This is the only step where you read the code. Read routes, controllers, form requests/validators, models (fillable/guarded, casts, scopes, relationships), policies/gates, middleware, migrations, jobs, listeners, events, observers, scheduled tasks, config, and the existing tests for the area. **If the feature has a UI, also read the frontend**: Blade/Livewire views and components, Inertia pages and shared props (`HandleInertiaRequests::share`), Vue/React/Alpine components, the API client (axios/fetch), client-side validation, and polling/websocket code. Note which API calls each component makes and which response fields it reads.
4. **Write `.swarm-court/scope.draft.md`** from `templates/scope.md.tmpl`. It is the ONLY thing the sub-agents know, because they cannot see this chat. It must contain: feature summary; file paths with a one-line role each; routes and HTTP verbs; the **frontend** (stack, pages/components with roles, the API calls and fields each one uses, auth/CSRF mechanism, frontend test commands, whether `node_modules` is installed); models and relationships; DB tables with constraints and indexes; jobs/queues; external services; the auth model (roles, policies, tenancy); business rules and state machines; **performance budgets** (p95 per endpoint, queries per request, job memory; "none" means the rubric defaults) and how to serve the app on 127.0.0.1 and seed a test DB at two sizes; how to run tests (exact commands); environment facts (APP_ENV, test DB name, queue driver: names only, never secret values); known gaps; and what is explicitly OUT of scope.

## Step 1: PLAN + CONSENT

1. **Choose lanes from the scope.** Start from all eleven and skip each lane whose `skip_when` (in `lanes.json`) applies:
   - `frontend`: run it whenever the scope includes browser code (Blade/Livewire views, Inertia pages, Vue/React/Svelte/Alpine). It hunts API-contract mismatches, stale-response races, client-only security, XSS sinks and leaked pollers. Skip it for API-only work.
   - `ui-ux`: skip if there are no views or components in scope.
   - `performance`: skip for trivial changes unless the user asked about it.
   - `queue-cache-external`: skip if there are no jobs, cache, webhooks or external calls.
   - `chaos-ops`: skip for a pure refactor with no config, deploy or migration impact.
   - `functional`, `authz-security` and `adversary`: almost never skip.

   Flags override your choice: `--lanes` forces exactly those lanes, `--skip` removes lanes, and `--quick` uses the 5 core lanes at depth 1, plus `frontend` when `QA detect` finds a frontend (add `--skip frontend` if the change is backend-only).
2. Run `QA plan --lanes <chosen> [--depth N] [--no-verify] [--wave W]` and show its table to the user: hunters, expected skeptics, total calls and waves.
3. **Consent:**
   - If the skill was triggered automatically (the user did not type `/swarm-court`), **ask before spending anything**.
   - If the user typed `/swarm-court`, show the plan and proceed, unless `plan` says `ASK FIRST` (more than 60 calls). In that case ask, and offer `--quick` or fewer lanes.

## Step 2: INIT

```
QA init --task-file .swarm-court/scope.draft.md --lanes <chosen> [--depth N] [--wave W] [--seed S] [--no-verify] --target "<one-line target>" --slug <short-slug>
```

This creates `.swarm-court/<YYYYMMDD-HHMMSS-slug>/`, copies scope.md in byte for byte, records its SHA-256, and writes `state.json`. After init, never edit the run's scope.md: `qa.py` refuses to write briefs if its hash changes. If the scope was wrong, start a new run.

## Step 3: THE LOOP (HUNT → VALIDATE → VERIFY → DEDUPE → REPORT)

Repeat until `QA next` says `DONE`:

```
QA next
```

It prints exactly one of these actions:

- **`NEXT: run this command`**: run it (`prompts hunt`, `validate`, `prompts verify`, `collect`, `dedupe` or `report`), then run `QA next` again.
- **`NEXT: spawn N ... agent(s) in ONE message`**: make N Agent calls in a single message, each with the printed `description` and `prompt` and `subagent_type: general-purpose`. Wait for the one-line replies, then run `QA next` again.
  - Hunters reply `<lane>-<n>: wrote K findings`. Skeptics reply `<finding-id>: <VERDICT>`.
  - If a hunter replied but its job is offered again, it forgot its `.done` marker. Run `QA mark hunt <job-id>` once.
  - A job offered 3 times with no output is marked failed, and the report lists it as a coverage gap.
- **`DONE`**: go to Step 4.

What happens inside, for your understanding only. Don't do any of it yourself:

- **HUNT**: one hunter per (lane × depth index). Hunters in the same lane get different *angles*: 1 code-reading, 2 test-first, 3 data-driven, 4 attacker, 5 historical, dealt round-robin (`--seed` rotates them reproducibly).
- **VALIDATE** (pure Python): rejects malformed or vague findings into `findings/_rejected/` with a reason. If more than 50% of a lane's findings were rejected, `next` spawns ONE fix-pass hunter for that lane.
- **VERIFY**: one skeptic per surviving finding. The skeptic sees scope.md plus the claim's title, what breaks, trigger and file:line, but never the hunter's reasoning. A verdict with no file:line is re-queued once and then becomes NEEDS-ENV. A performance finding stays CONFIRMED only if its `measurement:` file (a bench.py result, query counts or EXPLAIN output) exists inside `.swarm-court/<run>/tests/`. A race-condition finding stays CONFIRMED only if the skeptic set `parallel_test: yes` and named a test file inside `.swarm-court/<run>/tests/` that actually uses a parallel construct (`Process::pool`, `pcntl_fork`, `multiprocessing`, `Promise.all`, ...). Otherwise it is downgraded to LIKELY, with the reason recorded. With `--no-verify` this phase is skipped and every finding is UNVERIFIED.
- **DEDUPE** (pure Python): merges findings with the same root cause, keeps the strongest evidence and the highest severity, and gives findings that 2+ lanes found independently a `multi-lane` badge.
- **REPORT**: writes `REPORT.md` (including a Performance section built from every bench.py result: p50/p95/p99 against the budget, plus scaling at two data sizes) and `testcases.csv` in the run directory and applies the release gate from `rubric.md`.

## Step 4: SUMMARY (short, in chat)

Use the output of `QA report`. Do not open REPORT.md to write this. Format:

```
**Release gate: BLOCK**: <one-line reason>
Findings: CRITICAL n · HIGH n · MEDIUM n · LOW n   (CONFIRMED n · LIKELY n · NEEDS-ENV n · DISPUTED n)
Top issues:
1. <ID> <SEV> <VERDICT> <title> (<file:line>) [multi-lane]
... (3-5 items)
Coverage gaps: <skipped lanes; N checklist items unexamined; NEEDS-ENV items>
Report: .swarm-court/<run>/REPORT.md · Test cases: .swarm-court/<run>/testcases.csv
```

Then offer next steps, for example: "Fix RC-001 and I'll re-run only the race lane (`/swarm-court --rerun race`)", "Want me to copy the failing tests from `.swarm-court/<run>/tests/` into `tests/Feature/`?" (ask first), or "Run the NEEDS-ENV items against staging yourself."

## Flags

| Flag | Effect |
|---|---|
| *(none)* | scope from the text after the command, else the last request, else the current git diff |
| `--quick` | 5 core lanes (functional, race, integrity, authz, queue), depth 1, + `frontend` if the project has one |
| `--lanes race,authz` | only these lanes (aliases: race, authz, integrity, db, queue, perf, ui, ops, adv, func) |
| `--skip ui-ux,perf` | exclude lanes |
| `--depth N` | hunters per lane (default 2, max 5) |
| `--diff main` | scope = git diff against main |
| `--no-verify` | skip skeptics (cheaper, noisier; everything is UNVERIFIED and the gate cannot BLOCK) |
| `--wave W` | sub-agents per wave (default 10) |
| `--seed S` | reproducible angle dealing |
| `--rerun <lane>` | `QA rerun <lane>` makes a new run of one lane on the same scope.md (e.g. after a fix). Then loop on `QA next`. |

## Sub-agent briefs (exact text)

`QA prompts hunt|verify` writes these to `.swarm-court/<run>/briefs/`. Each brief also includes the lane's evidence standard, a stack note, the safety rules, the finding or verdict format, and a verbatim copy of scope.md between `-----BEGIN SCOPE.MD` and `-----END SCOPE.MD-----` markers. The text is reproduced here so you know what the agents were told. Do not paste it into Agent calls yourself.

### Hunter brief

```
You are a QA hunter in lane "{lane}" (hunter {n} of {depth}). Angle: {angle}.
Your ONLY source of context is .swarm-court/{run}/scope.md. Read it first.
Mission: {lane.mission}
Cover these checklist items: {lane.checklist}
Techniques: {lane.techniques}
Rules:
1. Read the real code before claiming anything. Cite file:line for every claim.
2. Report only bugs with a CONCRETE trigger: an input, sequence, or timing that
   causes them. No "might", "could be", "consider adding". No style nitpicks.
3. Max 8 findings, ranked by severity. Fewer, real findings beat many weak ones.
4. You may write and run tests ONLY inside .swarm-court/{run}/tests/. Never edit
   application source, config, migrations, or existing tests.
5. Never touch production or any non-test database. Before running anything that
   writes data, verify APP_ENV and the DB name are clearly test/local; otherwise
   do static analysis only.
6. Write each finding to .swarm-court/{run}/findings/{lane}-{n}-<k>.md using the
   finding format. Reply with ONE line: "{lane}-{n}: wrote K findings". Nothing else.
```

swarm-court adds two rules so it can resume and measure coverage:

```
7. BEFORE you reply, write .swarm-court/{run}/findings/{lane}-{n}.done with exactly two lines:
   findings: K
   covered: <comma-separated numbers of the checklist items above that you actually examined>
   qa.py uses this marker to know you finished and to build the coverage matrix.
8. Do not open other hunters' findings or anything under .swarm-court/{run}/verdicts/.
```

Angles: 1 `code-reading`: trace the code paths and find the bug by reading. 2 `test-first`: write failing tests first, then find the code that fails them. 3 `data-driven`: start from the schema and constraints and ask what the code lets violate them. 4 `attacker`: assume malicious input and abuse of every public entry point. 5 `historical`: look at git log/blame for recently changed or frequently patched areas and probe those first.

### Skeptic brief

```
You are a QA skeptic. A hunter claims the bug below. Your job is to DISPROVE it.
Read .swarm-court/{run}/scope.md, then the claim (title, trigger, file:line).
You have NOT seen the hunter's reasoning; form your own.
1. Read the cited code and everything it depends on (middleware, policies, scopes,
   observers, DB constraints, framework behaviour).
2. If a guard exists that prevents the trigger, verdict DISPUTED and cite file:line.
3. If you can reproduce it, write a failing test in .swarm-court/{run}/tests/ and run it.
   Verdict CONFIRMED with the test path and the observed output.
4. If the code path clearly allows it but you cannot reproduce it, verdict LIKELY and
   explain exactly what blocked reproduction.
5. If it needs infrastructure you lack, verdict NEEDS-ENV and say what's needed.
6. If the defect is real but unreachable today only because ANOTHER bug stops execution
   first, verdict LATENT and name the masking bug: it goes live once that one is fixed.
Race-condition claims: only CONFIRMED with a test using real parallelism.
Never edit application source. Never touch non-test databases.
Write .swarm-court/{run}/verdicts/{finding-id}.md using the verdict format.
Reply with ONE line: "{finding-id}: {VERDICT}".
```

The skeptic's claim block contains ONLY the finding ID, lane, claimed severity, title, location, "What breaks" and "Exact trigger". It never includes the hunter's "Why", suggested test or suggested fix.

## Reference files

- `lanes.json`: lane cards (mission, checklist, techniques, evidence standard, skip_when, default_depth). Editable.
- `rubric.md`: severity definitions, validation rules, verdicts, dedupe, release gate.
- `templates/`: scope, finding, verdict, report and test-case CSV header.
- `QA status`: progress per lane. `QA gate`: release gate alone. `QA plan --json` / `QA next --json`: machine-readable output.
