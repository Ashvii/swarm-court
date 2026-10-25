#!/usr/bin/env python3
"""swarm-court state machine for the /swarm-court Claude Code skill.

Pipeline: SCOPE -> PLAN -> HUNT -> VALIDATE -> VERIFY -> DEDUPE -> REPORT.

Sub-agents (hunters and skeptics) write files into .swarm-court/<run>/ and reply
with one line. Only this script reads those files, so the orchestrating
conversation stays small. All state lives in .swarm-court/<run>/state.json and is
written atomically; `qa.py next` can always reconstruct what to do.

Python 3.8+, standard library only. MIT licensed.
"""

import argparse
import csv
import datetime
import difflib
import hashlib
import io
import json
import math
import os
import random
import re
import string
import sys
import tempfile

VERSION = "1.0.2"
SKILL_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(SKILL_DIR, "templates")
LANES_PATH = os.path.join(SKILL_DIR, "lanes.json")
BENCH_PATH = os.path.join(SKILL_DIR, "bench.py")
RUNS_DIR = ".swarm-court"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEV_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
VERDICTS = ("CONFIRMED", "LIKELY", "LATENT", "DISPUTED", "NEEDS-ENV")
VERDICT_RANK = {"CONFIRMED": 5, "LIKELY": 4, "LATENT": 3, "NEEDS-ENV": 2, "UNVERIFIED": 1, "DISPUTED": 0}
TESTCASE_STATUS = {"CONFIRMED": "Fail", "LIKELY": "Blocked", "LATENT": "Blocked", "NEEDS-ENV": "Not tested",
                   "UNVERIFIED": "Not tested", "DISPUTED": "Pass"}
CATEGORIES = ("race", "authz", "integrity", "validation", "perf", "queue", "ui", "frontend", "ops", "logic")
REQUIRED_FIELDS = ("id", "lane", "title", "severity", "category", "location", "root_cause")
# (key, heading) in the order hunters must write them.
SECTIONS = (
    ("what", "What breaks"),
    ("why", "Why (code evidence)"),
    ("trigger", "Exact trigger"),
    ("expected", "Expected vs actual"),
    ("test", "Suggested test"),
    ("fix", "Suggested fix"),
)
ANGLES = (
    ("code-reading", "trace the code paths and find the bug by reading."),
    ("test-first", "write failing tests first, then find the code that fails them."),
    ("data-driven", "start from the schema and constraints and ask what the code lets violate them."),
    ("attacker", "assume malicious input and abuse of every public entry point."),
    ("historical", "look at git log/blame for recently changed or frequently patched areas "
                   "and probe those first."),
)
QUICK_LANES = ("functional", "race-conditions", "data-integrity", "authz-security", "queue-cache-external")
DEFAULT_DEPTH = 2
MAX_DEPTH = 5
DEFAULT_WAVE = 10
DEFAULT_EST_FINDINGS = 5   # typical valid findings per hunter
MAX_FINDINGS_PER_HUNTER = 8
CONSENT_THRESHOLD = 60
MAX_OFFERS = 3
RETRY_REJECT_RATIO = 0.5
# Dedupe thresholds (root-cause word overlap, Jaccard).
SPOT_LINES, SPOT_OVERLAP = 3, 0.10     # same file, within 3 lines: any shared root-cause words
NEAR_LINES, NEAR_OVERLAP = 10, 0.30    # same file, within 10 lines, same function: clearly shared root cause
STOPWORDS = set("the and for with from into via not only when then than this that are was has have does its any "
                "every each all which while same job".split())
SENSITIVE_LANES = ("race-conditions", "authz-security", "data-integrity")
SENSITIVE_CATEGORIES = ("race", "authz", "integrity")
SENSITIVE_TERMS = re.compile(
    r"payment|billing|invoice|charge|refund|inventory|stock|oversell|tenant|wallet|balance", re.I)

FILE_LINE_RE = re.compile(r"[A-Za-z0-9_./\\-]+\.[A-Za-z0-9]+:\d+")
LOCATION_RE = re.compile(r"^\s*`?(.+?):(\d+)")
HEDGE_RE = re.compile(r"\b(may|might|could|possibly|perhaps|potentially|maybe|consider)\b", re.I)
CONCRETE_RES = (
    re.compile(r"\d"),                                                   # a concrete value
    re.compile(r"[\"'`]"),                                               # a quoted value
    re.compile(r"[={}\[\]]"),                                            # payload / assignment
    re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b"),          # an HTTP verb
    re.compile(r"(^|\s)/[A-Za-z0-9_{}:.\-]+"),                           # a route
    re.compile(r"\b(then|while|after|before|followed by|meanwhile|during|simultaneously|"
               r"concurrently|in parallel|at the same time)\b", re.I),     # a sequence
    re.compile(r"\b(ms|milliseconds?|seconds?|minutes?|timeout|delay|expired?|expiry)\b", re.I),
)
HUNT_FILE_RE = re.compile(r"^(?P<hunter>(?P<lane>.+)-(?:\d+|fix))-(?P<k>\d+)\.md$")
# Constructs that run work in real parallel (separate processes, threads, connections or in-flight requests).
# A race CONFIRMED must point at a test file under .swarm-court/<run>/tests/ that uses one of them.
PARALLEL_RE = re.compile(
    r"Process::(?:pool|concurrently)|Concurrency::(?:run|defer)|Http::pool|pcntl_fork|proc_open|popen\s*\(|"
    r"curl_multi_exec|new\s+Process\s*\(|Spatie\\Async|Pool::create|parallel\\Runtime|"         # PHP
    r"multiprocessing|ProcessPoolExecutor|ThreadPoolExecutor|threading\.Thread|subprocess\.Popen|"
    r"asyncio\.gather|os\.fork|"                                                                # Python
    r"Promise\.all(?:Settled)?|worker_threads|child_process|cluster\.fork|"                     # JS / TS
    r"Thread\.new|Process\.fork|\bfork\s*\{|Parallel\.(?:map|each)|Concurrent::|"               # Ruby
    r"\bgo\s+func|sync\.WaitGroup|errgroup")                                                     # Go
# Function/method declarations, used to tell whether two nearby findings sit in the same function.
FUNC_RE = re.compile(r"^\s*(?:(?:public|protected|private|static|final|abstract|async|export|default|override)\s+)*"
                     r"(?:function|def|fn|func(?:\s+\([^)]*\))?)\s+&?(\w+)")

# ---------------------------------------------------------------------------
# Sub-agent briefs. SKILL.md quotes these verbatim; keep the two in sync.
# ---------------------------------------------------------------------------

HUNTER_BRIEF = """You are a QA hunter in lane "{lane}" (hunter {n} of {depth}). Angle: {angle}.
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
"""

HUNTER_BRIEF_EXTRA = """7. BEFORE you reply, write .swarm-court/{run}/findings/{lane}-{n}.done with exactly two lines:
   findings: K
   covered: <comma-separated numbers of the checklist items above that you actually examined>
   qa.py uses this marker to know you finished and to build the coverage matrix.
8. Do not open other hunters' findings or anything under .swarm-court/{run}/verdicts/.
"""

SKEPTIC_BRIEF = """You are a QA skeptic. A hunter claims the bug below. Your job is to DISPROVE it.
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
"""

SAFETY_RULES = """SAFETY RULES (hard requirements; breaking one makes your output worthless):
1. Never edit application source, config, migrations, or existing tests. Write only inside
   .swarm-court/{run}/. Generated tests stay there; applying them is the user's decision.
2. Never run anything that writes data unless APP_ENV is local/testing AND the DB name clearly
   indicates a test database. If unsure, static analysis only.
3. No load/stress testing. Latency is measured ONLY with the swarm-court bench tool against the local app
   (it refuses non-localhost targets and caps requests/concurrency/time). No calls to real external
   services or payment APIs; use fakes (Http::fake, Queue::fake, Event::fake or the stack's equivalent)
   or stop at LIKELY.
4. No exploit tooling or scanning outside the local test app.
5. No destructive commands (migrate:fresh on a non-test DB, rm -rf, DROP, TRUNCATE, etc.).
6. Secrets: never print .env values into findings, tests, logs or replies.
7. Never install or update dependencies (npm/yarn/pnpm/composer/pip install). Use only tooling already present.
   Dev servers and browsers: localhost only, never a public interface or a remote host.
"""

SCOPE_BEGIN = "-----BEGIN SCOPE.MD (verbatim copy of .swarm-court/{run}/scope.md, sha256 {sha})-----\n"
SCOPE_END = "\n-----END SCOPE.MD-----\n"


class QAError(Exception):
    pass


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def now_iso():
    return datetime.datetime.now().replace(microsecond=0).isoformat()


def slugify(text, limit=40):
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:limit].rstrip("-") or "run"


def norm(text):
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def natkey(name):
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", name)]


def fill(template, values):
    for key, value in values.items():
        template = template.replace("{" + key + "}", str(value))
    return template


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def read_text(path):
    return read_bytes(path).decode("utf-8", errors="replace")


def atomic_write(path, data):
    """Write to a temp file in the same directory, fsync, then rename over the target.

    A crash at any point leaves either the old file or the new file, never a torn one.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="surrogateescape")
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".part", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def strip_comments(text):
    return re.sub(r"<!--.*?-->", "", text or "", flags=re.S).strip()


def merge_evidence(front, body):
    """The verdict's front-matter evidence line, unless the Evidence section already cites it."""
    if front and body and front in body:
        return body
    return "\n".join(x for x in (front, body) if x)


def one_line(text, limit=160):
    s = re.sub(r"\s+", " ", strip_comments(text)).strip()
    return s if len(s) <= limit else s[:limit - 1].rstrip() + "…"


def truthy(value):
    return str(value or "").strip().lower() in ("yes", "y", "true", "1")


def py_cmd():
    return "python" if os.name == "nt" else "python3"


def qa_cmd(*args):
    parts = [py_cmd(), '"%s"' % os.path.abspath(__file__)] + list(args)
    return " ".join(parts)


def out(*lines):
    for line in lines:
        try:
            print(line)
        except UnicodeEncodeError:  # e.g. a cp1252 Windows console and an emoji in a title
            enc = getattr(sys.stdout, "encoding", None) or "ascii"
            print(line.encode(enc, errors="replace").decode(enc, errors="replace"))


def md_cell(text, limit=None):
    s = strip_comments(text or "")
    s = s.replace("|", "\\|").replace("\r", "")
    s = re.sub(r"\n+", "<br>", s.strip())
    if limit and len(s) > limit:
        s = s[:limit - 1].rstrip() + "…"
    return s


def read_template(name):
    return read_text(os.path.join(TEMPLATES_DIR, name))


# ---------------------------------------------------------------------------
# Markdown with frontmatter (findings and verdicts)
# ---------------------------------------------------------------------------

def parse_doc(text):
    """Return (frontmatter dict, {heading: body}) for a '---' frontmatter + '## ' sections doc."""
    text = text.replace("\r\n", "\n").lstrip("\ufeff")
    fm = {}
    body = text
    m = re.match(r"^\s*---[ \t]*\n(.*?)\n---[ \t]*(?:\n|$)", text, re.S)
    if m:
        for line in m.group(1).split("\n"):
            if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            value = re.sub(r"\s+#\s.*$", "", value).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            fm[key.strip().lower()] = value
        body = text[m.end():]
    sections = {}
    current = None
    for line in body.split("\n"):
        h = re.match(r"^##\s+(.+?)\s*$", line)
        if h and not line.startswith("###"):
            current = re.sub(r"\s+#\s.*$", "", h.group(1)).strip()
            sections[current] = []
            continue
        if current is not None:
            sections[current].append(line)
    return fm, {k: "\n".join(v).strip() for k, v in sections.items()}


def section_key(heading):
    h = norm(re.sub(r"\(.*?\)", "", heading))
    for prefix, key in (("what breaks", "what"), ("why", "why"), ("exact trigger", "trigger"),
                        ("trigger", "trigger"), ("expected", "expected"), ("suggested test", "test"),
                        ("test", "test"), ("suggested fix", "fix"), ("fix", "fix"),
                        ("preconditions", "preconditions"), ("reasoning", "reasoning"),
                        ("evidence", "evidence"), ("reproduction", "reproduction"),
                        ("what would settle", "needs")):
        if h.startswith(prefix):
            return key
    return h


def keyed_sections(sections):
    result = {}
    for heading, body in sections.items():
        key = section_key(heading)
        if key not in result:
            result[key] = body
    return result


def parse_location(location):
    m = LOCATION_RE.match(location or "")
    if not m:
        return None
    path = m.group(1).strip().strip("`").replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path, int(m.group(2))


def is_concrete(text):
    return any(r.search(text) for r in CONCRETE_RES)


# ---------------------------------------------------------------------------
# Lanes
# ---------------------------------------------------------------------------

def load_lanes():
    with open(LANES_PATH, encoding="utf-8") as fh:
        data = json.load(fh)
    return data["lanes"] if isinstance(data, dict) else data


def lane_map(lanes):
    return {lane["id"]: lane for lane in lanes}


def alias_map(lanes):
    amap = {}
    for lane in lanes:
        amap[lane["id"]] = lane["id"]
        for alias in lane.get("aliases", []):
            amap[alias.lower()] = lane["id"]
    return amap


def resolve_lane(name, lanes):
    lid = alias_map(lanes).get(name.strip().lower())
    if not lid:
        valid = ", ".join(l["id"] for l in lanes)
        raise QAError("unknown lane '%s'. Valid lanes: %s (aliases: race, authz, queue, db, perf, ...)"
                      % (name, valid))
    return lid


def split_list(value):
    return [v for v in re.split(r"[,\s]+", value or "") if v]


def choose_lanes(lanes, lanes_arg=None, skip_arg=None, quick=False, has_frontend=False):
    order = [l["id"] for l in lanes]
    if lanes_arg:
        chosen = {resolve_lane(x, lanes) for x in split_list(lanes_arg)}
    elif quick:
        chosen = set(QUICK_LANES)
        if has_frontend and "frontend" in order:
            chosen.add("frontend")
    else:
        chosen = set(order)
    for x in split_list(skip_arg):
        chosen.discard(resolve_lane(x, lanes))
    result = [lid for lid in order if lid in chosen]
    if not result:
        raise QAError("no lanes selected")
    return result


def lane_depths(lanes, chosen, depth=None, quick=False):
    if depth is not None and not (1 <= depth <= MAX_DEPTH):
        raise QAError("--depth must be between 1 and %d" % MAX_DEPTH)
    lm = lane_map(lanes)
    depths = {}
    for lid in chosen:
        if depth is not None:
            d = depth
        elif quick:
            d = 1
        else:
            d = int(lm[lid].get("default_depth", DEFAULT_DEPTH))
        depths[lid] = max(1, min(MAX_DEPTH, d))
    return depths


def deal_angles(lane_id, depth, seed=None):
    """Round-robin by depth index. A seed rotates the starting angle per lane, reproducibly."""
    offset = 0 if seed is None else random.Random("%s:%s" % (seed, lane_id)).randrange(len(ANGLES))
    return [ANGLES[(offset + i) % len(ANGLES)][0] for i in range(depth)]


# ---------------------------------------------------------------------------
# Stack detection
# ---------------------------------------------------------------------------

def load_json_file(p):
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def package_deps(path):
    data = load_json_file(path)
    deps = dict(data.get("dependencies", data.get("require", {})) or {})
    deps.update(data.get("devDependencies", data.get("require-dev", {})) or {})
    return deps


def has_blade_views(project, limit=2000):
    views = os.path.join(project, "resources", "views")
    seen = 0
    for _root, _dirs, files in os.walk(views):
        for name in files:
            if name.endswith(".blade.php"):
                return True
            seen += 1
            if seen > limit:
                return False
    return False


def detect_frontend(project):
    """Browser-side stack, or None when the project has no frontend code."""
    npm = package_deps(os.path.join(project, "package.json"))
    php = package_deps(os.path.join(project, "composer.json"))
    checks = (
        ("inertia", any(k.startswith("@inertiajs/") for k in npm) or "inertiajs/inertia-laravel" in php),
        ("livewire", "livewire/livewire" in php),
        ("next", "next" in npm), ("nuxt", "nuxt" in npm), ("angular", "@angular/core" in npm),
        ("vue", "vue" in npm), ("react", "react" in npm), ("svelte", "svelte" in npm),
        ("alpine", "alpinejs" in npm), ("blade", has_blade_views(project)),
    )
    frameworks = [name for name, present in checks if present]
    if not frameworks:
        return None
    unit = next((r for r in ("vitest", "jest") if r in npm), None)
    e2e = next((r for r in ("@playwright/test", "cypress") if r in npm), None)
    installed = os.path.isdir(os.path.join(project, "node_modules"))
    commands = {"vitest": "npx vitest run", "jest": "npx jest"}
    return {"frameworks": frameworks, "unit_runner": unit, "unit_command": commands.get(unit),
            "e2e_runner": e2e.replace("@playwright/test", "playwright") if e2e else None,
            "testing_library": any(k.startswith("@testing-library/") or k == "@vue/test-utils" for k in npm),
            "node_modules": installed}


def detect_stack(project):
    info = detect_backend(project)
    info["frontend"] = detect_frontend(project)
    return info


def detect_backend(project):
    def path(*parts):
        return os.path.join(project, *parts)

    load_json = load_json_file

    if os.path.isfile(path("composer.json")):
        data = load_json(path("composer.json"))
        deps = dict(data.get("require", {}) or {})
        deps.update(data.get("require-dev", {}) or {})
        runner = "pest" if "pestphp/pest" in deps else "phpunit"
        if "laravel/framework" in deps or os.path.isfile(path("artisan")):
            return {"stack": "laravel", "language": "php", "test_runner": runner,
                    "test_command": "php artisan test", "evidence": "composer.json"}
        return {"stack": "php", "language": "php", "test_runner": runner,
                "test_command": "vendor/bin/%s" % runner, "evidence": "composer.json"}
    if os.path.isfile(path("package.json")):
        data = load_json(path("package.json"))
        deps = dict(data.get("dependencies", {}) or {})
        deps.update(data.get("devDependencies", {}) or {})
        framework = next((f for f in ("next", "@nestjs/core", "express", "fastify", "koa", "@remix-run/node",
                                      "nuxt", "@sveltejs/kit") if f in deps), "node")
        runner = next((r for r in ("vitest", "jest", "mocha", "@playwright/test") if r in deps), "npm test")
        return {"stack": "node:%s" % framework.replace("@", "").split("/")[0], "language": "javascript",
                "test_runner": runner, "test_command": "npm test", "evidence": "package.json"}
    py_files = [f for f in ("pyproject.toml", "requirements.txt", "setup.py", "manage.py") if os.path.isfile(path(f))]
    if py_files:
        blob = " ".join(read_text(path(f)).lower() for f in py_files if f != "manage.py")
        if os.path.isfile(path("manage.py")) or "django" in blob:
            return {"stack": "django", "language": "python", "test_runner": "pytest" if "pytest" in blob else "django",
                    "test_command": "pytest" if "pytest" in blob else "python manage.py test",
                    "evidence": py_files[0]}
        framework = next((f for f in ("fastapi", "flask") if f in blob), "python")
        return {"stack": framework, "language": "python", "test_runner": "pytest",
                "test_command": "pytest", "evidence": py_files[0]}
    if os.path.isfile(path("Gemfile")):
        blob = read_text(path("Gemfile")).lower()
        rspec = "rspec" in blob
        return {"stack": "rails" if "rails" in blob else "ruby", "language": "ruby",
                "test_runner": "rspec" if rspec else "minitest",
                "test_command": "bundle exec rspec" if rspec else "bin/rails test", "evidence": "Gemfile"}
    if os.path.isfile(path("go.mod")):
        return {"stack": "go", "language": "go", "test_runner": "go test",
                "test_command": "go test ./...", "evidence": "go.mod"}
    return {"stack": "unknown", "language": "unknown", "test_runner": "unknown",
            "test_command": "(see scope.md)", "evidence": ""}


# ---------------------------------------------------------------------------
# Run / state
# ---------------------------------------------------------------------------

class Ctx(object):
    def __init__(self, project, run_id):
        self.project = project
        self.run_id = run_id
        self.run_dir = os.path.join(project, RUNS_DIR, run_id)
        self.lanes = load_lanes()
        self.lm = lane_map(self.lanes)
        self.state = load_state(self.run_dir)

    def rel(self, *parts):
        return "/".join((RUNS_DIR, self.run_id) + parts)

    def abs(self, rel_path):
        return os.path.join(self.project, *rel_path.split("/"))

    def path(self, *parts):
        return os.path.join(self.run_dir, *parts)

    def save(self):
        save_state(self.run_dir, self.state)


def load_state(run_dir):
    path = os.path.join(run_dir, "state.json")
    if not os.path.isfile(path):
        raise QAError("no state.json in %s (run `qa.py init` first)" % run_dir)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_state(run_dir, state):
    state["updated"] = now_iso()
    atomic_write(os.path.join(run_dir, "state.json"), json.dumps(state, indent=2) + "\n")


def open_run(args):
    project = os.path.abspath(args.project)
    run_id = args.run
    if not run_id:
        pointer = os.path.join(project, RUNS_DIR, "CURRENT")
        if not os.path.isfile(pointer):
            raise QAError("no current run in %s (run `qa.py init` first, or pass --run)" % project)
        run_id = read_text(pointer).strip()
    return Ctx(project, run_id)


def check_scope(ctx):
    actual = hashlib.sha256(read_bytes(ctx.path("scope.md"))).hexdigest()
    if actual != ctx.state["scope_sha256"]:
        raise QAError("scope.md changed since init (sha256 %s != %s). Start a new run instead of editing it."
                      % (actual[:12], ctx.state["scope_sha256"][:12]))


def scope_text(ctx):
    return read_bytes(ctx.path("scope.md")).decode("utf-8", errors="surrogateescape")


def hunt_job(run_id, lane_id, n, depth, angle, fix=False):
    jid = "%s-%s" % (lane_id, "fix" if fix else n)
    return {"id": jid, "lane": lane_id, "n": "fix" if fix else n, "depth": depth, "angle": angle,
            "fix": fix, "status": "pending", "offers": 0, "covered": [], "reported": None,
            "brief_path": "%s/%s/briefs/hunt/%s.md" % (RUNS_DIR, run_id, jid),
            "marker": "%s/%s/findings/%s.done" % (RUNS_DIR, run_id, jid)}


def create_run(project, run_id, scope_bytes, lanes, chosen, depths, wave, seed, verify, target, stack, flags):
    run_dir = os.path.join(project, RUNS_DIR, run_id)
    for sub in ("findings/_rejected", "verdicts/_rejected", "tests", "briefs/hunt", "briefs/verify"):
        os.makedirs(os.path.join(run_dir, *sub.split("/")), exist_ok=True)
    atomic_write(os.path.join(run_dir, "scope.md"), scope_bytes)
    jobs = []
    for lid in chosen:
        for i, angle in enumerate(deal_angles(lid, depths[lid], seed)):
            jobs.append(hunt_job(run_id, lid, i + 1, depths[lid], angle))
    depth_values = sorted(set(depths.values()))
    state = {
        "version": VERSION,
        "run_id": run_id,
        "created": now_iso(),
        "updated": now_iso(),
        "seed": seed,
        "scope_sha256": hashlib.sha256(scope_bytes).hexdigest(),
        "target": target,
        "stack": stack,
        "flags": flags,
        "lanes": chosen,
        "depth": depth_values[0] if len(depth_values) == 1 else max(depth_values),
        "lane_depth": depths,
        "wave": wave,
        "verify": verify,
        "phase": "scoped",
        "jobs": {"hunt": jobs, "verify": []},
        "findings": {},
        "seen_files": [],
        "retried_lanes": [],
        "counters": {},
        "verify_prompts": False,
        "deduped": False,
        "gate": {"result": None, "reasons": []},
    }
    save_state(run_dir, state)
    atomic_write(os.path.join(project, RUNS_DIR, "CURRENT"), run_id + "\n")
    gitignore = os.path.join(project, RUNS_DIR, ".gitignore")
    if not os.path.exists(gitignore):
        atomic_write(gitignore, "*\n")
    return run_dir, state


def new_run_id(project, slug):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_id = "%s-%s" % (stamp, slug)
    i = 2
    while os.path.exists(os.path.join(project, RUNS_DIR, run_id)):
        run_id = "%s-%s-%d" % (stamp, slug, i)
        i += 1
    return run_id


def first_heading(text):
    m = re.search(r"^#\s+(.+)$", text, re.M)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------

def compute_plan(chosen, depths, verify=True, est=DEFAULT_EST_FINDINGS, wave=DEFAULT_WAVE):
    rows = []
    for lid in chosen:
        h = depths[lid]
        rows.append({"lane": lid, "hunters": h, "skeptics": h * est if verify else 0})
    hunters = sum(r["hunters"] for r in rows)
    skeptics = sum(r["skeptics"] for r in rows)
    hunt_waves = int(math.ceil(hunters / float(wave))) if hunters else 0
    verify_waves = int(math.ceil(skeptics / float(wave))) if skeptics else 0
    total = hunters + skeptics
    worst = hunters + len(chosen) + (skeptics * 2 if verify else 0)
    return {"rows": rows, "lanes": len(chosen), "hunters": hunters, "skeptics": skeptics,
            "total": total, "hunt_waves": hunt_waves, "verify_waves": verify_waves,
            "waves": hunt_waves + verify_waves, "worst_case": worst, "wave": wave,
            "est_findings": est, "verify": verify, "needs_consent": total > CONSENT_THRESHOLD}


def print_plan(plan, depths):
    depth_values = sorted(set(depths.values()))
    depth_label = str(depth_values[0]) if len(depth_values) == 1 else "mixed"
    out("swarm-court plan",
        "lanes: %d   depth: %s   wave: %d   verify: %s   est. findings/hunter: %d"
        % (plan["lanes"], depth_label, plan["wave"], "yes" if plan["verify"] else "no (UNVERIFIED)",
           plan["est_findings"]),
        "",
        "%-24s %8s %14s" % ("lane", "hunters", "est.skeptics"),
        "%-24s %8s %14s" % ("-" * 24, "-" * 8, "-" * 14))
    for r in plan["rows"]:
        out("%-24s %8d %14d" % (r["lane"], r["hunters"], r["skeptics"]))
    out("%-24s %8d %14d" % ("TOTAL", plan["hunters"], plan["skeptics"]),
        "",
        "sub-agent calls (expected): %d = %d hunters + %d skeptics"
        % (plan["total"], plan["hunters"], plan["skeptics"]),
        "waves: %d (%d hunt + %d verify, <= %d agents each)"
        % (plan["waves"], plan["hunt_waves"], plan["verify_waves"], plan["wave"]),
        "upper bound with every retry: %d calls" % plan["worst_case"],
        "consent: %s" % ("ASK FIRST (more than %d calls)" % CONSENT_THRESHOLD if plan["needs_consent"]
                         else "not required (<= %d calls)" % CONSENT_THRESHOLD))


def cmd_plan(args):
    lanes = load_lanes()
    chosen = choose_lanes(lanes, args.lanes, args.skip, args.quick,
                          bool(detect_frontend(os.path.abspath(args.project))))
    depths = lane_depths(lanes, chosen, args.depth, args.quick)
    est = DEFAULT_EST_FINDINGS if args.est_findings is None else args.est_findings
    if est < 0:
        raise QAError("--est-findings must be >= 0")
    plan = compute_plan(chosen, depths, not args.no_verify, est, args.wave or DEFAULT_WAVE)
    if args.json:
        out(json.dumps(plan, indent=2))
    else:
        print_plan(plan, depths)
    return 0


# ---------------------------------------------------------------------------
# init / rerun / detect
# ---------------------------------------------------------------------------

def cmd_init(args):
    project = os.path.abspath(args.project)
    lanes = load_lanes()
    chosen = choose_lanes(lanes, args.lanes, args.skip, args.quick,
                          bool(detect_frontend(os.path.abspath(args.project))))
    depths = lane_depths(lanes, chosen, args.depth, args.quick)
    if not args.task_file or not os.path.isfile(args.task_file):
        raise QAError("--task-file must point to the scope.md you wrote")
    scope = read_bytes(args.task_file)
    if not scope.strip():
        raise QAError("scope file is empty")
    wave = args.wave or DEFAULT_WAVE
    if wave < 1:
        raise QAError("--wave must be >= 1")
    slug = slugify(args.slug or args.target or first_heading(scope.decode("utf-8", "replace")))
    run_id = new_run_id(project, slug)
    stack = detect_stack(project)
    if args.stack:
        stack["stack"] = args.stack
    flags = {"quick": bool(args.quick), "no_verify": bool(args.no_verify), "lanes": args.lanes,
             "skip": args.skip, "depth": args.depth, "wave": wave, "rerun_of": None}
    run_dir, state = create_run(project, run_id, scope, lanes, chosen, depths, wave, args.seed,
                                not args.no_verify, args.target or first_heading(scope.decode("utf-8", "replace")),
                                stack, flags)
    print_init(state, run_dir)
    return 0


def print_init(state, run_dir):
    out("run: %s" % state["run_id"],
        "dir: %s" % run_dir,
        "scope sha256: %s" % state["scope_sha256"],
        "stack: %s (test command: %s)" % (state["stack"]["stack"], state["stack"]["test_command"]),
        "frontend: %s" % (", ".join(state["stack"]["frontend"]["frameworks"])
                          if state["stack"].get("frontend") else "none detected"),
        "lanes (%d): %s" % (len(state["lanes"]), ", ".join(state["lanes"])),
        "hunters: %d   wave: %d   verify: %s"
        % (len(state["jobs"]["hunt"]), state["wave"], "yes" if state["verify"] else "no"),
        "next: %s" % qa_cmd("next"))


def cmd_rerun(args):
    project = os.path.abspath(args.project)
    lanes = load_lanes()
    lane_id = resolve_lane(args.lane, lanes)
    prev_args = argparse.Namespace(project=project, run=args.source or args.run)
    prev = open_run(prev_args)
    ps = prev.state
    scope = read_bytes(prev.path("scope.md"))
    depth = ps.get("lane_depth", {}).get(lane_id) or ps.get("depth") or DEFAULT_DEPTH
    depths = {lane_id: int(depth)}
    slug = slugify("%s-rerun-%s" % (ps["run_id"][16:] or "run", lane_id))
    run_id = new_run_id(project, slug)
    flags = dict(ps.get("flags", {}))
    flags.update({"lanes": lane_id, "skip": None, "rerun_of": ps["run_id"]})
    run_dir, state = create_run(project, run_id, scope, lanes, [lane_id], depths, ps.get("wave", DEFAULT_WAVE),
                                ps.get("seed"), ps.get("verify", True), ps.get("target"),
                                ps.get("stack") or detect_stack(project), flags)
    out("rerun of %s (same scope, lane %s)" % (ps["run_id"], lane_id))
    print_init(state, run_dir)
    return 0


def cmd_detect(args):
    info = detect_stack(os.path.abspath(args.project))
    if args.json:
        out(json.dumps(info, indent=2))
    else:
        for key in ("stack", "language", "test_runner", "test_command", "evidence"):
            out("%s: %s" % (key, info[key]))
        out("frontend: %s" % (frontend_note(info["frontend"]) if info.get("frontend") else "none detected"))
    return 0


# ---------------------------------------------------------------------------
# Briefs
# ---------------------------------------------------------------------------

def scope_block(ctx):
    begin = fill(SCOPE_BEGIN, {"run": ctx.run_id, "sha": ctx.state["scope_sha256"]})
    return begin + scope_text(ctx) + SCOPE_END


def stack_note(ctx):
    st = ctx.state.get("stack") or {}
    name = st.get("stack", "unknown")
    note = "Stack: detected \"%s\" (default test command: %s; scope.md has the exact commands)." % (
        name, st.get("test_command", "see scope.md"))
    if name != "laravel":
        note += (" This is NOT Laravel: translate every Laravel-specific technique above into its equivalent "
                 "for this stack (locks, transactions, policies, queue/HTTP fakes, test runner).")
    fe = st.get("frontend")
    if fe:
        note += "\n" + frontend_note(fe)
    return note


def frontend_note(fe):
    note = "Frontend: %s." % ", ".join(fe["frameworks"])
    if fe.get("unit_runner"):
        note += " Component tests: %s%s." % (fe["unit_command"], " + Testing Library" if fe.get("testing_library") else "")
    if fe.get("e2e_runner"):
        note += " E2E runner present: %s (localhost only)." % fe["e2e_runner"]
    if not fe.get("node_modules"):
        note += (" node_modules is NOT installed: JS tests cannot run. Do not install anything; reason statically "
                 "(a field the component reads that the API provably never returns is a deterministic proof), "
                 "or reproduce logic in a small standalone script under .swarm-court/<run>/tests/ with plain node if "
                 "`node` exists.")
    if "livewire" in fe["frameworks"]:
        note += " Livewire components are testable from PHP with Livewire::test() when vendor/ exists."
    return note


def hunter_brief(ctx, job):
    lane = ctx.lm[job["lane"]]
    checklist = "\n" + "\n".join("  %d. %s" % (i + 1, item) for i, item in enumerate(lane["checklist"]))
    techniques = "\n" + "\n".join("  - %s" % t for t in lane.get("techniques", []))
    angle = dict(ANGLES).get(job["angle"], "")
    values = {"lane": lane["id"], "n": job["n"], "depth": job["depth"],
              "angle": "%s (%s)" % (job["angle"], angle.rstrip(".")), "run": ctx.run_id,
              "lane.mission": lane["mission"], "lane.checklist": checklist, "lane.techniques": techniques}
    text = fill(HUNTER_BRIEF, values)
    if job["fix"]:
        rest = text.split("\n", 1)[1]
        text = ('You are a QA hunter in lane "%s" (FIX PASS: more than half of this lane\'s findings were '
                'rejected). Angle: %s.\n' % (lane["id"], values["angle"])) + rest
    text += fill(HUNTER_BRIEF_EXTRA, values)
    parts = [text, "", root_note(ctx), "Evidence standard for this lane: %s" % lane.get("evidence_standard", ""),
             stack_note(ctx), ""]
    if lane["id"] == "performance":
        parts += [bench_note(ctx), ""]
    if job["fix"]:
        parts += ["WHY YOU WERE SPAWNED: these findings from your lane were rejected by qa.py validate. "
                  "Read each one, fix what made it invalid (or drop it if it cannot be made concrete), and "
                  "write the corrected findings as NEW files .swarm-court/%s/findings/%s-fix-<k>.md:" % (
                      ctx.run_id, lane["id"])]
        for f in sorted(ctx.state["findings"].values(), key=lambda x: natkey(x["file"])):
            if f["status"] == "rejected" and f["lane"] == lane["id"] and not f["hunter"].endswith("-fix"):
                parts.append("  - %s: %s" % (f["file"], f["reject_reason"]))
        parts.append("")
    parts += [fill(SAFETY_RULES, {"run": ctx.run_id}),
              "FINDING FORMAT (one file per finding; every frontmatter key and all six ## sections are "
              "required; replace the <!-- comments -->):",
              "```markdown", read_template("finding.md.tmpl").rstrip("\n"), "```", "",
              "AUTOMATIC REJECTION (qa.py validate): missing field or section; severity not "
              "CRITICAL/HIGH/MEDIUM/LOW; location without file:line or file not in the repo; Exact trigger "
              "under 40 characters or with no concrete value, HTTP verb/route, sequence (then/while/after) or "
              "timing; hedging-only title/trigger; empty Suggested test; CRITICAL/HIGH without a file:line "
              "in Why; more than 8 findings.", ""]
    return "\n".join(parts) + "\n" + scope_block(ctx)


def finding_claim(ctx, finding):
    sec = keyed_sections(parse_doc(read_text(ctx.abs(finding["file"])))[1])
    return {"title": finding["title"], "severity": finding["severity"], "lane": finding["lane"],
            "location": finding["location"], "what": strip_comments(sec.get("what", "")),
            "trigger": strip_comments(sec.get("trigger", ""))}


def skeptic_brief(ctx, job):
    finding = ctx.state["findings"][job["finding_id"]]
    claim = finding_claim(ctx, finding)
    values = {"run": ctx.run_id, "finding-id": finding["id"]}
    parts = [fill(SKEPTIC_BRIEF, values), "", root_note(ctx), "",
             "THE CLAIM",
             "Finding ID: %s" % finding["id"],
             "Lane: %s   Claimed severity: %s" % (claim["lane"], claim["severity"]),
             "Title: %s" % claim["title"],
             "Location: %s" % claim["location"],
             "What breaks:", claim["what"], "",
             "Exact trigger:", claim["trigger"], ""]
    if finding["lane"] == "race-conditions" or finding.get("category") == "race":
        parts += ["This is a race-condition claim. CONFIRMED requires ALL of: (a) a test file saved under "
                  ".swarm-court/%s/tests/ and named in `test:`; (b) that test runs the trigger with real "
                  "parallelism: separate processes or DB connections released by a barrier (e.g. Process::pool, "
                  "Concurrency::run, pcntl_fork, proc_open, Http::pool against a running server, or the stack's "
                  "equivalent: multiprocessing, Promise.all, threads, goroutines); (c) `parallel_test: yes`. "
                  "qa.py checks the file exists there and uses a parallel construct; otherwise it downgrades "
                  "CONFIRMED to LIKELY. Calling the endpoint twice in sequence does not count." % ctx.run_id, ""]
    if is_perf(finding):
        parts += ["This is a performance claim. CONFIRMED requires `measurement:` naming a file under "
                  ".swarm-court/%s/tests/ that holds the measurement (a bench.py JSON result, or captured "
                  "query-count / EXPLAIN / memory output). Otherwise qa.py downgrades CONFIRMED to LIKELY. A "
                  "single slow sample on a laptop proves nothing; growth with data size does." % ctx.run_id,
                  bench_note(ctx), ""]
    if job.get("requeue_reason"):
        parts += ["YOUR PREVIOUS VERDICT FOR THIS FINDING WAS REJECTED: %s. Every verdict must cite at least "
                  "one file:line (e.g. app/Http/Controllers/OrderController.php:42)." % job["requeue_reason"], ""]
    parts += ["Do not open anything under .swarm-court/%s/findings/ (that is the hunter's reasoning)." % ctx.run_id,
              stack_note(ctx), "",
              fill(SAFETY_RULES, {"run": ctx.run_id}),
              "VERDICT FORMAT (write exactly this structure):",
              "```markdown", fill(read_template("verdict.md.tmpl"), values).rstrip("\n"), "```", ""]
    return "\n".join(parts) + "\n" + scope_block(ctx)


def write_brief(ctx, kind, job):
    text = hunter_brief(ctx, job) if kind == "hunt" else skeptic_brief(ctx, job)
    atomic_write(ctx.abs(job["brief_path"]), text)


def bench_note(ctx):
    bench = '%s "%s"' % (py_cmd(), BENCH_PATH)
    out = ".swarm-court/%s/tests/bench" % ctx.run_id
    return (
        "LATENCY MEASUREMENT: time things ONLY with the swarm-court bench tool, which refuses non-localhost targets "
        "and caps every run at 500 requests, 8 concurrent, 60 s (a measurement, never a load test):\n"
        "  %s http http://127.0.0.1:<port>/api/... -n 50 -c 1 --budget-ms <p95 budget> --label <name> "
        "--out %s/<name>.json\n"
        "  %s cmd -n 10 --label <name> --out %s/<name>.json -- php .swarm-court/%s/tests/<script>.php\n"
        "  %s compare %s/<small>.json %s/<large>.json --size-small 1000 --size-large 10000\n"
        "Serve the app (or a minimal reproduction) on 127.0.0.1 only, e.g. `php artisan serve --host=127.0.0.1` "
        "or `php -S 127.0.0.1:8099 -t <dir>`, and stop it when done. Absolute numbers on this machine are "
        "noisy; the strong evidence is SCALING: measure the same endpoint at two data sizes (e.g. 1k and 10k rows "
        "seeded into a test SQLite DB) and report the growth (`compare`). Also capture query counts "
        "(DB::listen / query log) and, for jobs/exports, peak memory (memory_get_peak_usage). Budgets come from "
        "scope.md; if none are given use rubric defaults (API p95 <= 500 ms, <= 10 queries per request, "
        "flat or sublinear growth). Never put real tokens in --header values that end up in findings."
        % (bench, out, bench, out, ctx.run_id, bench, out, out))


def root_note(ctx):
    return ("PROJECT ROOT: %s\nEvery relative path in this brief (including .swarm-court/...) is relative to that "
            "directory. Resolve paths against it, whatever your current working directory is." % ctx.project)


def agent_call(ctx, kind, job):
    brief = ctx.abs(job["brief_path"])
    return {"id": job["id"], "description": "qa %s %s" % (kind, job["id"]), "brief": job["brief_path"],
            "prompt": "Read %s and follow it exactly. Reply with ONE line only." % brief}


def print_waves(ctx, kind, jobs):
    wave = ctx.state["wave"]
    if not jobs:
        out("no %s jobs pending" % kind)
        return
    total = int(math.ceil(len(jobs) / float(wave)))
    out("%s briefs written: %d jobs in %d wave(s) of <= %d" % (kind, len(jobs), total, wave))
    for w in range(total):
        chunk = jobs[w * wave:(w + 1) * wave]
        out("wave %d: %s" % (w + 1, ", ".join(j["id"] for j in chunk)))
    out("next: %s" % qa_cmd("next"))


def cmd_prompts(args):
    ctx = open_run(args)
    check_scope(ctx)
    st = ctx.state
    if args.kind == "hunt":
        jobs = [j for j in st["jobs"]["hunt"] if j["status"] == "pending"]
        for job in jobs:
            write_brief(ctx, "hunt", job)
        if st["phase"] == "scoped":
            st["phase"] = "hunting"
    else:
        if st["phase"] != "verifying":
            raise QAError("verify briefs are written in the verifying phase (current: %s). Run `qa.py next`."
                          % st["phase"])
        existing = {j["finding_id"] for j in st["jobs"]["verify"]}
        for fid in sorted(st["findings"], key=natkey):
            f = st["findings"][fid]
            if f["status"] == "new" and fid not in existing:
                st["jobs"]["verify"].append({
                    "id": fid, "finding_id": fid, "status": "pending", "offers": 0, "requeues": 0,
                    "requeue_reason": None,
                    "brief_path": ctx.rel("briefs", "verify", fid + ".md"),
                    "verdict_path": ctx.rel("verdicts", fid + ".md")})
        jobs = [j for j in st["jobs"]["verify"] if j["status"] == "pending"]
        for job in jobs:
            write_brief(ctx, "verify", job)
        st["verify_prompts"] = True
    ctx.save()
    print_waves(ctx, args.kind, jobs)
    return 0


# ---------------------------------------------------------------------------
# next / mark / status
# ---------------------------------------------------------------------------

def parse_marker(text):
    info = {"findings": None, "covered": []}
    for line in text.replace("\r\n", "\n").split("\n"):
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key == "findings":
            m = re.search(r"\d+", value)
            info["findings"] = int(m.group()) if m else None
        elif key == "covered":
            info["covered"] = sorted({int(x) for x in re.findall(r"\d+", value)})
    return info


def refresh_hunt(ctx):
    changed = False
    for job in ctx.state["jobs"]["hunt"]:
        if job["status"] == "pending" and os.path.isfile(ctx.abs(job["marker"])):
            info = parse_marker(read_text(ctx.abs(job["marker"])))
            job.update({"status": "done", "covered": info["covered"], "reported": info["findings"]})
            changed = True
    return changed


def refresh_verify(ctx):
    changed = False
    for job in ctx.state["jobs"]["verify"]:
        if job["status"] == "pending" and os.path.isfile(ctx.abs(job["verdict_path"])):
            job["status"] = "returned"
            changed = True
    return changed


def expire_offers(ctx, kind):
    """A job handed out MAX_OFFERS times without output is given up on (recorded as a gap)."""
    for job in ctx.state["jobs"][kind]:
        if job["status"] == "pending" and job["offers"] >= MAX_OFFERS:
            job["status"] = "failed"
            if kind == "verify":
                f = ctx.state["findings"][job["finding_id"]]
                f["verdict"] = "NEEDS-ENV"
                f["verdict_note"] = "skeptic produced no verdict after %d attempts" % MAX_OFFERS


def compute_next(ctx):
    """Decide the single next action. Mutates job offer counters; caller saves."""
    st = ctx.state
    phase = st["phase"]
    if phase == "scoped":
        return {"action": "run", "argv": ["prompts", "hunt"], "why": "write hunter briefs"}
    if phase in ("hunting", "validating"):
        refresh_hunt(ctx)
        expire_offers(ctx, "hunt")
        pending = [j for j in st["jobs"]["hunt"] if j["status"] == "pending"]
        if pending:
            return spawn(ctx, "hunt", pending)
        return {"action": "run", "argv": ["validate"], "why": "all hunters reported; validate their findings"}
    if phase == "verifying":
        if not st["verify_prompts"]:
            return {"action": "run", "argv": ["prompts", "verify"], "why": "write skeptic briefs"}
        refresh_verify(ctx)
        expire_offers(ctx, "verify")
        pending = [j for j in st["jobs"]["verify"] if j["status"] == "pending"]
        if pending:
            return spawn(ctx, "verify", pending)
        return {"action": "run", "argv": ["collect"], "why": "collect skeptic verdicts"}
    if phase == "deduping":
        if not st["deduped"]:
            return {"action": "run", "argv": ["dedupe"], "why": "merge same-root-cause findings"}
        return {"action": "run", "argv": ["report"], "why": "write REPORT.md and testcases.csv"}
    if phase == "reported":
        return {"action": "done", "report": ctx.rel("REPORT.md"), "testcases": ctx.rel("testcases.csv")}
    raise QAError("unknown phase %r in state.json" % phase)


def spawn(ctx, kind, pending):
    batch = pending[:ctx.state["wave"]]
    calls = []
    for job in batch:
        if not os.path.isfile(ctx.abs(job["brief_path"])):
            write_brief(ctx, kind, job)
        job["offers"] += 1
        calls.append(agent_call(ctx, kind, job))
    return {"action": "spawn", "kind": kind, "calls": calls, "pending": len(pending),
            "remaining_after": len(pending) - len(batch)}


def cmd_next(args):
    ctx = open_run(args)
    action = compute_next(ctx)
    ctx.save()
    action["phase"] = ctx.state["phase"]
    action["run"] = ctx.run_id
    if action["action"] == "run":
        action["command"] = qa_cmd(*action["argv"])
    action["then"] = qa_cmd("next")
    if args.json:
        out(json.dumps(action, indent=2))
        return 0
    out("RUN %s   PHASE %s" % (ctx.run_id, action["phase"]))
    if action["action"] == "run":
        out("NEXT: run this command (%s):" % action["why"], "  " + action["command"])
    elif action["action"] == "spawn":
        out("NEXT: spawn %d %s agent(s) in ONE message (subagent_type: general-purpose); %d more after this wave."
            % (len(action["calls"]), action["kind"], action["remaining_after"]),
            "      Do not open the files they write. Each replies with one line.")
        for call in action["calls"]:
            out('  - description: "%s"' % call["description"], '    prompt: "%s"' % call["prompt"])
        out("THEN: " + action["then"])
    else:
        out("DONE. Report: %s" % action["report"], "      Test cases: %s" % action["testcases"],
            "      Summary: " + qa_cmd("report"))
    return 0


def cmd_mark(args):
    ctx = open_run(args)
    jobs = {j["id"]: j for j in ctx.state["jobs"]["hunt"]}
    for jid in args.ids:
        if jid not in jobs:
            raise QAError("unknown hunt job %s" % jid)
        if jobs[jid]["status"] == "pending":
            jobs[jid]["status"] = "done"
            jobs[jid]["covered"] = []
            jobs[jid]["reported"] = None
    ctx.save()
    out("marked done: %s" % ", ".join(args.ids))
    return 0


def lane_stats(st, lane_id):
    hunts = [j for j in st["jobs"]["hunt"] if j["lane"] == lane_id]
    fs = [f for f in st["findings"].values() if f["lane"] == lane_id]
    return {"hunters": len(hunts), "done": sum(1 for j in hunts if j["status"] == "done"),
            "accepted": sum(1 for f in fs if f["status"] != "rejected"),
            "rejected": sum(1 for f in fs if f["status"] == "rejected"),
            "final": sum(1 for f in fs if f["status"] == "final")}


def cmd_status(args):
    ctx = open_run(args)
    refresh_hunt(ctx)
    refresh_verify(ctx)
    st = ctx.state
    out("run: %s   phase: %s   target: %s" % (st["run_id"], st["phase"], st.get("target") or "-"),
        "",
        "%-24s %9s %9s %9s %7s" % ("lane", "hunters", "accepted", "rejected", "final"))
    for lid in st["lanes"]:
        s = lane_stats(st, lid)
        out("%-24s %4d/%-4d %9d %9d %7d" % (lid, s["done"], s["hunters"], s["accepted"], s["rejected"], s["final"]))
    live = [f for f in st["findings"].values() if f["status"] in ("new", "final")]
    counts = {}
    for f in live:
        v = f.get("verdict") or ("UNVERIFIED" if not st["verify"] else "PENDING")
        counts[v] = counts.get(v, 0) + 1
    out("", "verdicts: " + (", ".join("%s %d" % (k, counts[k]) for k in sorted(counts)) or "none yet"),
        "pending jobs: hunt %d, verify %d" % (
            sum(1 for j in st["jobs"]["hunt"] if j["status"] == "pending"),
            sum(1 for j in st["jobs"]["verify"] if j["status"] in ("pending", "returned"))),
        "failed jobs: %s" % (", ".join(j["id"] for k in ("hunt", "verify") for j in st["jobs"][k]
                                       if j["status"] == "failed") or "none"))
    if st["gate"].get("result"):
        out("gate: %s" % st["gate"]["result"])
    return 0


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

def check_finding(project, fm, sections, lanes):
    """Return (reason, None) for a reject or (None, record) for a valid finding."""
    missing = [k for k in REQUIRED_FIELDS if not fm.get(k)]
    if missing:
        return "missing frontmatter field(s): %s" % ", ".join(missing), None
    severity = fm["severity"].strip().upper()
    if severity not in SEVERITIES:
        return "bad severity '%s' (allowed: %s)" % (fm["severity"], ", ".join(SEVERITIES)), None
    lane_id = alias_map(lanes).get(fm["lane"].strip().lower())
    if not lane_id:
        return "unknown lane '%s'" % fm["lane"], None
    sec = keyed_sections(sections)
    for key, title in SECTIONS:
        if key not in sec:
            return "missing section: ## %s" % title, None
    for key, title in SECTIONS:
        if key != "test" and not strip_comments(sec[key]):
            return "empty section: ## %s" % title, None
    if not strip_comments(sec["test"]):
        return "empty suggested test", None
    loc = parse_location(fm["location"])
    if not loc:
        return "location '%s' has no file:line" % fm["location"], None
    path, line = loc
    if os.path.isabs(path) and os.path.isfile(path):
        path = os.path.relpath(path, project).replace(os.sep, "/")
    if not os.path.isfile(os.path.join(project, path)):
        return "location file does not exist in the repo: %s" % path, None
    trigger = strip_comments(sec["trigger"])
    concrete = is_concrete(trigger)
    if len(trigger) < 40:
        return "exact trigger too short (%d chars, need >= 40)" % len(trigger), None
    if not concrete and (HEDGE_RE.search(fm["title"]) or HEDGE_RE.search(trigger)):
        return "hedging-only trigger (no concrete input, sequence or timing)", None
    if not concrete:
        return "vague trigger: no concrete value, HTTP verb/route, sequence or timing", None
    if severity in ("CRITICAL", "HIGH") and not FILE_LINE_RE.search(strip_comments(sec["why"])):
        return "%s finding without file:line evidence in 'Why'" % severity, None
    category = fm["category"].strip().lower()
    record = {"lane": lane_id, "title": fm["title"].strip(), "severity": severity,
              "orig_severity": severity, "category": category,
              "location": "%s:%d" % (path, line), "path": path, "line": line,
              "root_cause": fm["root_cause"].strip(), "status": "new", "verdict": None,
              "verdict_note": "", "verdict_evidence": "", "verdict_reason": "", "verdict_needs": "",
              "test": "", "parallel_test": False, "merged_from": [], "merged_into": None,
              "found_by_lanes": [lane_id], "multi_lane": False, "reject_reason": None}
    return None, record


def cmd_validate(args):
    ctx = open_run(args)
    st = ctx.state
    refresh_hunt(ctx)
    pending = [j["id"] for j in st["jobs"]["hunt"] if j["status"] == "pending"]
    if pending and not args.force:
        raise QAError("%d hunt job(s) still pending (%s). Run `qa.py next`, or pass --force."
                      % (len(pending), ", ".join(pending[:5])))
    fdir = ctx.path("findings")
    seen = set(st["seen_files"])
    files = sorted((f for f in os.listdir(fdir) if f.endswith(".md") and f not in seen
                    and os.path.isfile(os.path.join(fdir, f))), key=natkey)
    results = []
    for fname in files:
        m = HUNT_FILE_RE.match(fname)
        hunter = m.group("hunter") if m else fname[:-3]
        fm, sections = parse_doc(read_text(os.path.join(fdir, fname)))
        reason, record = check_finding(ctx.project, fm, sections, ctx.lanes)
        lane_guess = (record or {}).get("lane") or alias_map(ctx.lanes).get(
            (fm.get("lane") or "").lower()) or (m.group("lane") if m else "unknown")
        results.append({"file": fname, "hunter": hunter, "lane": lane_guess, "reason": reason,
                        "record": record, "fm": fm})

    by_hunter = {}
    for r in results:
        if not r["reason"]:
            by_hunter.setdefault(r["hunter"], []).append(r)
    for hunter, items in by_hunter.items():
        items.sort(key=lambda r: (-SEV_RANK[r["record"]["severity"]], natkey(r["file"])))
        for r in items[MAX_FINDINGS_PER_HUNTER:]:
            r["reason"] = "over-cap: hunter %s wrote more than %d findings (lowest severity rejected)" % (
                hunter, MAX_FINDINGS_PER_HUNTER)
            r["record"] = None

    for r in results:
        st["seen_files"].append(r["file"])
        src = os.path.join(fdir, r["file"])
        if r["reason"]:
            dst = os.path.join(fdir, "_rejected", r["file"])
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(src, dst)
            atomic_write(dst + ".reason.txt", r["reason"] + "\n")
            st["findings"]["REJ:" + r["file"]] = {
                "id": "REJ:" + r["file"], "lane": r["lane"], "hunter": r["hunter"],
                "title": r["fm"].get("title", ""), "severity": (r["fm"].get("severity") or "").upper(),
                "status": "rejected", "reject_reason": r["reason"],
                "file": ctx.rel("findings", "_rejected", r["file"])}
            continue
        rec = r["record"]
        prefix = ctx.lm[rec["lane"]].get("prefix") or rec["lane"][:2].upper()
        st["counters"][prefix] = st["counters"].get(prefix, 0) + 1
        fid = "%s-%03d" % (prefix, st["counters"][prefix])
        text = read_text(src)
        text = re.sub(r"(?m)^id:.*$", "id: %s" % fid, text, count=1)
        atomic_write(src, text)
        rec.update({"id": fid, "hunter": r["hunter"], "file": ctx.rel("findings", r["file"])})
        st["findings"][fid] = rec

    fix_jobs = []
    for lid in st["lanes"]:
        if lid in st["retried_lanes"]:
            continue
        fs = [f for f in st["findings"].values() if f["lane"] == lid and not f["hunter"].endswith("-fix")]
        rejected = sum(1 for f in fs if f["status"] == "rejected")
        if fs and rejected / float(len(fs)) > RETRY_REJECT_RATIO:
            job = hunt_job(st["run_id"], lid, "fix", st["lane_depth"].get(lid, 1), "code-reading", fix=True)
            st["jobs"]["hunt"].append(job)
            st["retried_lanes"].append(lid)
            fix_jobs.append(job)
            write_brief(ctx, "hunt", job)

    if fix_jobs:
        st["phase"] = "hunting"
    else:
        new = [f for f in st["findings"].values() if f["status"] == "new"]
        if not st["verify"]:
            for f in new:
                f["verdict"] = "UNVERIFIED"
            st["phase"] = "deduping"
        elif not [f for f in new if not f.get("verdict")]:
            st["phase"] = "deduping"
        else:
            st["phase"] = "verifying"
            st["verify_prompts"] = False
    ctx.save()

    out("validated %d new finding file(s)" % len(results), "",
        "%-24s %9s %9s" % ("lane", "accepted", "rejected"))
    for lid in st["lanes"]:
        s = lane_stats(st, lid)
        out("%-24s %9d %9d" % (lid, s["accepted"], s["rejected"]))
    reasons = {}
    for r in results:
        if r["reason"]:
            key = r["reason"].split(":")[0].split("(")[0].strip()
            reasons[key] = reasons.get(key, 0) + 1
    if reasons:
        out("", "rejection reasons: " + "; ".join("%s x%d" % (k, v) for k, v in sorted(reasons.items())))
    if fix_jobs:
        out("", "fix pass queued (>50%% rejected): %s" % ", ".join(j["id"] for j in fix_jobs))
    out("next: %s" % qa_cmd("next"))
    return 0


# ---------------------------------------------------------------------------
# collect
# ---------------------------------------------------------------------------

def is_perf(finding):
    return finding["lane"] == "performance" or finding.get("category") == "perf"


def is_race(finding):
    return finding["lane"] == "race-conditions" or finding.get("category") == "race"


def resolve_run_test(ctx, test):
    """Find the skeptic's test file. It must exist inside .swarm-court/<run>/tests/; returns its path or None."""
    tests_dir = os.path.realpath(ctx.path("tests"))
    rel = test.strip().strip("`").replace("\\", "/")
    candidates = [rel if os.path.isabs(rel) else os.path.join(ctx.project, *rel.split("/")),
                  os.path.join(ctx.run_dir, *rel.split("/")),
                  os.path.join(tests_dir, *rel.split("/"))]
    for cand in candidates:
        real = os.path.realpath(cand)
        if os.path.isfile(real) and os.path.commonpath([real, tests_dir]) == tests_dir:
            return real
    return None


def parallel_test_problem(ctx, claimed, test):
    """Why a race CONFIRMED is not backed by a real-parallelism test, or None if it is."""
    if not claimed:
        return "race claims need a real-parallelism test (parallel_test: yes)"
    if not test:
        return "parallel_test: yes but no test file named"
    path = resolve_run_test(ctx, test)
    if not path:
        return "test file %s not found inside %s" % (test, ctx.rel("tests") + "/")
    if not PARALLEL_RE.search(read_text(path)):
        return ("test %s uses no parallel construct (separate processes, threads, connections or "
                "concurrent requests)" % test)
    return None


def normalize_verdict(value):
    v = re.sub(r"[\s_]+", "-", (value or "").strip().upper())
    return "NEEDS-ENV" if v in ("NEEDSENV", "NEEDS-ENVIRONMENT") else v


def cmd_collect(args):
    ctx = open_run(args)
    st = ctx.state
    refresh_verify(ctx)
    tally = {"recorded": 0, "requeued": 0, "gave_up": 0, "downgraded": 0}
    for job in st["jobs"]["verify"]:
        if job["status"] != "returned":
            continue
        finding = st["findings"][job["finding_id"]]
        vpath = ctx.abs(job["verdict_path"])
        text = read_text(vpath)
        fm, sections = parse_doc(text)
        sec = keyed_sections(sections)
        verdict = normalize_verdict(fm.get("verdict"))
        body = re.sub(r"^\s*---.*?\n---[ \t]*\n", "", text.replace("\r\n", "\n"), count=1, flags=re.S)
        evidence_blob = (fm.get("evidence") or "") + "\n" + strip_comments(body)
        reason = None
        if verdict not in VERDICTS:
            reason = "invalid verdict value '%s'" % (fm.get("verdict") or "")
        elif not FILE_LINE_RE.search(evidence_blob):
            reason = "no file:line evidence"
        if reason:
            attempt = job["requeues"] + 1
            dst = ctx.path("verdicts", "_rejected", "%s.attempt%d.md" % (job["finding_id"], attempt))
            os.replace(vpath, dst)
            atomic_write(dst + ".reason.txt", reason + "\n")
            if job["requeues"] < 1:
                job.update({"requeues": 1, "status": "pending", "offers": 0, "requeue_reason": reason})
                write_brief(ctx, "verify", job)
                tally["requeued"] += 1
            else:
                job["status"] = "collected"
                finding.update({"verdict": "NEEDS-ENV",
                                "verdict_note": "skeptic verdict rejected twice (%s); needs a human or "
                                                "the right environment to settle" % reason})
                tally["gave_up"] += 1
            continue
        note = ""
        test = "" if norm(fm.get("test")) in ("", "none", "n a", "na", "no") else fm["test"].strip()
        parallel = False
        if verdict == "CONFIRMED" and is_race(finding):
            problem = parallel_test_problem(ctx, truthy(fm.get("parallel_test")), test)
            if problem:
                verdict = "LIKELY"
                note = "downgraded CONFIRMED -> LIKELY: %s" % problem
                tally["downgraded"] += 1
            else:
                parallel = True
        measurement = "" if norm(fm.get("measurement")) in ("", "none", "n a", "na", "no") else \
            fm["measurement"].strip()
        if verdict == "CONFIRMED" and is_perf(finding) and not (measurement and resolve_run_test(ctx, measurement)):
            verdict = "LIKELY"
            note = ("downgraded CONFIRMED -> LIKELY: performance claims need a measurement file inside %s/ "
                    "(bench.py result or captured query-count/EXPLAIN output)" % ctx.rel("tests"))
            tally["downgraded"] += 1
        finding.update({
            "verdict": verdict, "verdict_note": note, "parallel_test": parallel,
            "test": test, "measurement": measurement,
            "verdict_evidence": merge_evidence(fm.get("evidence", "").strip(),
                                               strip_comments(sec.get("evidence", ""))),
            "verdict_reason": strip_comments(sec.get("reasoning", "")),
            "verdict_repro": strip_comments(sec.get("reproduction", "")),
            "verdict_needs": strip_comments(sec.get("needs", ""))})
        job["status"] = "collected"
        tally["recorded"] += 1
    if all(j["status"] in ("collected", "failed") for j in st["jobs"]["verify"]):
        st["phase"] = "deduping"
    ctx.save()
    counts = {}
    for f in st["findings"].values():
        if f["status"] == "new" and f.get("verdict"):
            counts[f["verdict"]] = counts.get(f["verdict"], 0) + 1
    out("collected: %d recorded, %d re-queued (no file:line), %d gave up -> NEEDS-ENV, %d race downgrades"
        % (tally["recorded"], tally["requeued"], tally["gave_up"], tally["downgraded"]),
        "verdicts: " + (", ".join("%s %d" % (k, counts[k]) for k in sorted(counts)) or "none"),
        "next: %s" % qa_cmd("next"))
    return 0


# ---------------------------------------------------------------------------
# dedupe
# ---------------------------------------------------------------------------

def enclosing_function(project, path, line, cache):
    """Name of the nearest function/method declared at or above `line`, or None if unknown."""
    if (path, line) in cache:
        return cache[(path, line)]
    if path not in cache:
        full = os.path.join(project, path) if project else None
        try:
            cache[path] = read_text(full).splitlines() if full and os.path.isfile(full) else None
        except OSError:
            cache[path] = None
    lines = cache[path]
    name = None
    if lines:
        for text in reversed(lines[:max(0, min(line, len(lines)))]):
            m = FUNC_RE.match(text)
            if m:
                name = m.group(1)
                break
    cache[(path, line)] = name
    return name


def text_ratio(a, b):
    return difflib.SequenceMatcher(None, norm(a["title"] + " " + a["root_cause"]),
                                   norm(b["title"] + " " + b["root_cause"])).ratio()


def tokens(text):
    words = re.findall(r"[a-z0-9_]+", (text or "").lower())
    return {w for w in words if (len(w) > 2 or w.isdigit()) and w not in STOPWORDS}


def root_overlap(a, b):
    """Jaccard overlap of the significant words in two root causes (0..1)."""
    ta, tb = tokens(a["root_cause"]), tokens(b["root_cause"])
    return len(ta & tb) / float(len(ta | tb) or 1)


def same_issue(a, b, func_of=None):
    """Return the rule name that makes a and b the same issue, or None.

    Duplicates from different lanes cite the same line but often use different categories, while different
    bugs in one function sit on different lines with unrelated root causes. Merging is deliberately
    conservative: a missed merge shows a duplicate, a wrong merge hides a bug.
    """
    ra, rb = norm(a["root_cause"]), norm(b["root_cause"])
    if ra and ra == rb:
        return "same-root-cause"
    if a["path"] != b["path"]:
        return None
    distance = abs(a["line"] - b["line"])
    overlap = root_overlap(a, b)
    if distance <= SPOT_LINES and overlap >= SPOT_OVERLAP:
        return "same-spot"
    if distance <= NEAR_LINES and overlap >= NEAR_OVERLAP:
        fa = func_of(a) if func_of else None
        fb = func_of(b) if func_of else None
        if not (fa and fb) or fa == fb:
            return "same-function"
    if text_ratio(a, b) >= 0.75:
        return "fuzzy-title"
    return None


def verdict_of(f):
    return f.get("verdict") or "UNVERIFIED"


def dedupe_groups(findings, project=None):
    """Union-find over pairs. DISPUTED and non-DISPUTED findings are never joined."""
    items = sorted(findings, key=lambda f: natkey(f["id"]))
    parent = list(range(len(items)))
    rules = {}
    cache = {}

    def func_of(f):
        return enclosing_function(project, f["path"], f["line"], cache)

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            a, b = items[i], items[j]
            if (verdict_of(a) == "DISPUTED") != (verdict_of(b) == "DISPUTED"):
                continue
            rule = same_issue(a, b, func_of)
            if rule:
                rules[(a["id"], b["id"])] = rule
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[max(ri, rj)] = min(ri, rj)
    groups = {}
    for i, f in enumerate(items):
        groups.setdefault(find(i), []).append(f)
    return list(groups.values()), rules


def cmd_dedupe(args):
    ctx = open_run(args)
    st = ctx.state
    if st["phase"] not in ("deduping", "reported") and not args.force:
        raise QAError("dedupe runs after verification (current phase: %s). Run `qa.py next`." % st["phase"])
    lane_order = {l["id"]: i for i, l in enumerate(ctx.lanes)}
    items = [f for f in st["findings"].values() if f["status"] in ("new", "final", "merged")]
    for f in items:
        f.update({"status": "new", "merged_from": [], "merged_into": None, "found_by_lanes": [f["lane"]],
                  "multi_lane": False, "severity": f.get("orig_severity", f["severity"])})
    groups, rules = dedupe_groups(items, ctx.project)
    merges = []
    for group in groups:
        group.sort(key=lambda f: (-VERDICT_RANK[verdict_of(f)], -SEV_RANK[f["severity"]], natkey(f["id"])))
        keeper = group[0]
        lanes_found = sorted({f["lane"] for f in group}, key=lambda l: lane_order.get(l, 99))
        keeper.update({"status": "final", "found_by_lanes": lanes_found, "multi_lane": len(lanes_found) >= 2,
                       "severity": max((f["severity"] for f in group), key=lambda s: SEV_RANK[s]),
                       "merged_from": sorted((f["id"] for f in group[1:]), key=natkey)})
        if not keeper.get("test"):
            keeper["test"] = next((f["test"] for f in group if f.get("test")), "")
        for f in group[1:]:
            f.update({"status": "merged", "merged_into": keeper["id"]})
        if len(group) > 1:
            merges.append(keeper)
    st["deduped"] = True
    st["dedupe_rules"] = ["%s ~ %s (%s)" % (a, b, r) for (a, b), r in sorted(rules.items())]
    st["phase"] = "deduping"
    ctx.save()
    finals = [f for f in items if f["status"] == "final"]
    out("dedupe: %d findings -> %d unique (%d merged)" % (len(items), len(finals), len(items) - len(finals)))
    for k in merges:
        out("  %s <- %s%s" % (k["id"], ", ".join(k["merged_from"]), "  [multi-lane]" if k["multi_lane"] else ""))
    out("next: %s" % qa_cmd("next"))
    return 0


# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------

def final_findings(st):
    status = "final" if st.get("deduped") else "new"
    return [f for f in st["findings"].values() if f["status"] == status]


def sensitivity(f):
    """Why a HIGH finding blocks release: a sensitive lane/category or a payments/inventory/tenant topic."""
    lanes = [l for l in (f.get("found_by_lanes") or [f["lane"]]) if l in SENSITIVE_LANES]
    if lanes:
        return "lane " + ", ".join(lanes)
    if f.get("category") in SENSITIVE_CATEGORIES:
        return "category " + f["category"]
    if f.get("category") in ("perf", "ui", "frontend", "ops"):
        return ""   # a slow invoice query is not a billing-correctness bug
    m = SENSITIVE_TERMS.search(" ".join((f.get("title", ""), f.get("root_cause", ""), f.get("location", ""))))
    return ("touches " + m.group(0).lower()) if m else ""


def is_sensitive(f):
    return bool(sensitivity(f))


def coverage(st, lanes):
    """Rows of (lane, index, item, covered_by[], status)."""
    rows = []
    for lane in lanes:
        run = lane["id"] in st["lanes"]
        jobs = [j for j in st["jobs"]["hunt"] if j["lane"] == lane["id"] and j["status"] == "done"]
        for i, item in enumerate(lane["checklist"], 1):
            by = [j["id"] for j in jobs if i in (j.get("covered") or [])]
            status = "skipped" if not run else ("covered" if by else "NOT COVERED")
            rows.append({"lane": lane["id"], "index": i, "item": item, "by": by, "status": status})
    return rows


def compute_gate(st, lanes):
    block, warn = [], []
    for f in sorted(final_findings(st), key=lambda f: (-SEV_RANK[f["severity"]], natkey(f["id"]))):
        v = verdict_of(f)
        if v == "DISPUTED":
            continue
        label = "%s %s %s: %s" % (f["id"], f["severity"], v, f["title"])
        if v == "LATENT":
            if f["severity"] != "LOW":
                warn.append(label + " (latent: masked by another bug; goes live when that is fixed, re-run then)")
        elif v in ("CONFIRMED", "LIKELY"):
            if f["severity"] == "CRITICAL":
                block.append(label)
            elif f["severity"] == "HIGH" and is_sensitive(f):
                block.append(label + " (HIGH in a sensitive area: %s)" % sensitivity(f))
            elif f["severity"] in ("HIGH", "MEDIUM"):
                warn.append(label)
        elif f["severity"] in ("CRITICAL", "HIGH"):
            warn.append(label + " (not verified: %s)" % v)
        elif f["severity"] == "MEDIUM":
            warn.append(label)
    result = "BLOCK" if block else ("WARN" if warn else "PASS")
    reasons = (["BLOCK: " + b for b in block] + ["WARN: " + w for w in warn]) or [
        "no findings above LOW severity survived verification"]
    if not st.get("verify", True):
        reasons.append("verification skipped (--no-verify): every finding is UNVERIFIED")
    rows = coverage(st, lanes)
    gaps = {
        "skipped_lanes": [l["id"] for l in lanes if l["id"] not in st["lanes"]],
        "uncovered": ["%s #%d %s" % (r["lane"], r["index"], r["item"]) for r in rows if r["status"] == "NOT COVERED"],
        "needs_env": ["%s: %s" % (f["id"], f["title"]) for f in final_findings(st) if verdict_of(f) == "NEEDS-ENV"],
        "failed_jobs": [j["id"] for k in ("hunt", "verify") for j in st["jobs"][k] if j["status"] == "failed"],
    }
    return {"result": result, "reasons": reasons, "gaps": gaps}


def cmd_gate(args):
    ctx = open_run(args)
    gate = compute_gate(ctx.state, ctx.lanes)
    ctx.state["gate"] = gate
    ctx.save()
    if args.json:
        out(json.dumps(gate, indent=2))
        return 0
    out("RELEASE GATE: %s" % gate["result"])
    for r in gate["reasons"]:
        out("  - " + r)
    print_gaps(gate["gaps"])
    return 0


def print_gaps(gaps):
    out("coverage gaps:",
        "  lanes skipped: %s" % (", ".join(gaps["skipped_lanes"]) or "none"),
        "  checklist items nobody examined: %d" % len(gaps["uncovered"]),
        "  NEEDS-ENV: %d" % len(gaps["needs_env"]),
        "  failed jobs: %s" % (", ".join(gaps["failed_jobs"]) or "none"))


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def sort_key(f):
    return (-SEV_RANK[f["severity"]], -VERDICT_RANK[verdict_of(f)], natkey(f["id"]))


def finding_sections(ctx, f):
    path = ctx.abs(f["file"])
    if not os.path.isfile(path):
        return {}
    return {k: strip_comments(v) for k, v in keyed_sections(parse_doc(read_text(path))[1]).items()}


def code_block(text, lang=""):
    if "```" in text:
        return text
    return "```%s\n%s\n```" % (lang, text)


def test_lang(ctx):
    language = (ctx.state.get("stack") or {}).get("language", "")
    return {"php": "php", "python": "python", "javascript": "js", "ruby": "ruby", "go": "go"}.get(language, "")


def split_expected(text):
    exp = re.search(r"(?im)^\s*[-*]?\s*\**expected\**\s*[:\-]\s*(.+)$", text)
    act = re.search(r"(?im)^\s*[-*]?\s*\**actual\**\s*[:\-]\s*(.+)$", text)
    if exp or act:
        return (exp.group(1).strip() if exp else ""), (act.group(1).strip() if act else "")
    return text, ""


def render_finding(ctx, f, sec):
    badge = "  `multi-lane`" if f.get("multi_lane") else ""
    lines = ["#### %s · %s · %s%s" % (f["id"], f["severity"], f["title"], badge), "",
             "- **Verdict:** %s%s" % (verdict_of(f), (" (%s)" % f["verdict_note"]) if f.get("verdict_note") else ""),
             "- **Location:** `%s`" % f["location"],
             "- **Found by:** %s%s" % (", ".join(f["found_by_lanes"]),
                                       ("; merged from %s" % ", ".join(f["merged_from"])) if f["merged_from"] else ""),
             "- **Category / root cause:** %s / %s" % (f["category"], f["root_cause"]), ""]
    if sec.get("what"):
        lines += ["**What breaks.** " + sec["what"], ""]
    lines += ["**Exact trigger**", "", sec.get("trigger", "(missing)"), "",
              "**Evidence (hunter)**", "", sec.get("why", "(missing)"), ""]
    if f.get("verdict_evidence") or f.get("verdict_reason"):
        lines += ["**Skeptic's evidence**", "", "\n\n".join(x for x in (f.get("verdict_evidence"),
                                                                     f.get("verdict_reason")) if x), ""]
    if sec.get("expected"):
        lines += ["**Expected vs actual**", "", sec["expected"], ""]
    lines.append("**Failing test**%s" % (" (written by the skeptic: `%s`)" % f["test"] if f.get("test") else ""))
    lines += ["", code_block(sec.get("test", "(none)"), test_lang(ctx)), "",
              "**Suggested fix**", "", sec.get("fix", "(none)"), ""]
    return "\n".join(lines)


def testcase_rows(ctx, finals, secs):
    feat = re.sub(r"[^A-Z0-9]+", "", (ctx.run_id[16:] or "RUN").upper())[:12] or "RUN"
    feature = ctx.state.get("target") or ctx.run_id[16:]
    rows = []
    for i, f in enumerate(finals, 1):
        sec = secs[f["id"]]
        trigger = sec.get("trigger", "")
        expected, actual = split_expected(sec.get("expected", ""))
        data = re.findall(r"`([^`\n]+)`", trigger) + re.findall(r"\{[^{}\n]*\}", trigger)
        if not actual:
            actual = {"CONFIRMED": f.get("verdict_repro") or "Reproduced (see report)",
                      "DISPUTED": "Guarded (skeptic disproved the claim)"}.get(verdict_of(f), "Not yet observed")
        pre = sec.get("preconditions") or ("APP_ENV=testing with a test database; code at %s" % f["location"])
        rows.append(["QA-%s-%03d" % (feat, i), feature, "%s (%s)" % (f["title"], f["id"]), one_line(pre, 300),
                     "; ".join(data[:6]) or "See steps", one_line(trigger, 600), one_line(expected, 400),
                     one_line(actual, 400), f["severity"], TESTCASE_STATUS[verdict_of(f)]])
    return rows


def bench_results(ctx):
    """Every swarm-court-bench JSON file written under the run's tests/ directory, sorted by path."""
    results = []
    root = ctx.path("tests")
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".json"):
                continue
            path = os.path.join(dirpath, name)
            data = load_json_file(path)
            if isinstance(data, dict) and data.get("tool") == "swarm-court-bench":
                data["_file"] = os.path.relpath(path, ctx.project).replace(os.sep, "/")
                results.append(data)
    return sorted(results, key=lambda d: natkey(d["_file"]))


SIZE_LABEL_RE = re.compile(r"^(?P<base>.*?)[-_ ]?(?P<num>\d+(?:\.\d+)?)(?P<unit>[kKmM]?)$")


def auto_scaling(timed):
    """Pair results whose labels differ only by a data size (index-1k / index-10k) and compute the growth."""
    groups = {}
    for r in timed:
        m = SIZE_LABEL_RE.match(str(r.get("label") or ""))
        if not m or not r.get("p95_ms") or not m.group("base").strip("-_ "):
            continue
        size = float(m.group("num")) * {"k": 1e3, "m": 1e6}.get(m.group("unit").lower(), 1)
        groups.setdefault((m.group("base").strip("-_ "), r.get("kind")), []).append((size, r))
    rows = []
    for _group, items in sorted(groups.items()):
        sizes = sorted(items, key=lambda x: x[0])
        (s_small, small), (s_large, large) = sizes[0], sizes[-1]
        if s_large <= s_small:
            continue
        growth = large["p95_ms"] / small["p95_ms"]
        exponent = math.log(growth) / math.log(s_large / s_small) if growth > 0 else 0.0
        scaling = ("superlinear" if exponent > 1.2 else "linear" if exponent > 0.7
                   else "sublinear" if exponent > 0.25 else "flat")
        rows.append({"label": "%s vs %s" % (small["label"], large["label"]),
                     "small": {"p95_ms": small["p95_ms"]}, "large": {"p95_ms": large["p95_ms"]},
                     "size_growth": round(s_large / s_small, 2), "p95_growth": round(growth, 2),
                     "exponent": round(exponent, 2), "scaling": scaling, "auto": True})
    return rows


def performance_md(ctx):
    results = bench_results(ctx)
    if not results:
        return ("_No latency measurements were taken. Run the `performance` lane (with the app served on "
                "127.0.0.1) to measure p50/p95/p99 and scaling with data size._")
    timed = [r for r in results if r.get("kind") in ("http", "cmd")]
    compares = [r for r in results if r.get("kind") == "compare"]
    known = {r.get("label") for r in compares}
    compares += [r for r in auto_scaling(timed) if r["label"] not in known]
    lines = ["All numbers come from `bench.py` against the local app: they show relative cost and growth, "
             "not production latency.", ""]
    if timed:
        lines += ["| Label | Target | n / conc | ok / err | p50 ms | p95 ms | p99 ms | Budget | Result |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for r in timed:
            budget = ("%g ms" % r["budget_ms"]) if r.get("budget_ms") else "-"
            result = "**OVER**" if r.get("over_budget") else ("ok" if r.get("budget_ms") else "-")
            lines.append("| %s | `%s` | %s / %s | %s / %s | %s | %s | %s | %s | %s |" % (
                md_cell(r.get("label")), md_cell(r.get("target"), 70), r.get("requested"), r.get("concurrency"),
                r.get("ok"), r.get("errors"), r.get("p50_ms"), r.get("p95_ms"), r.get("p99_ms"), budget, result))
    if compares:
        lines += ["", "**Scaling** (same operation at two data sizes; exponent 1 = linear. Pairs are matched "
                  "automatically by label, e.g. `index-1k` / `index-10k`):", "",
                  "| Comparison | p95 small -> large | Data growth | Latency growth | Exponent | Scaling |",
                  "|---|---|---|---|---|---|"]
        for r in compares:
            flag = "**%s**" % r["scaling"] if r.get("scaling") == "superlinear" else r.get("scaling")
            lines.append("| %s | %s -> %s ms | x%s | x%s | %s | %s |" % (
                md_cell(r.get("label")), r["small"].get("p95_ms"), r["large"].get("p95_ms"),
                r.get("size_growth") or "?", r.get("p95_growth"), r.get("exponent"), flag))
    return "\n".join(lines)


def cmd_report(args):
    ctx = open_run(args)
    st = ctx.state
    if not st["deduped"]:
        raise QAError("run `qa.py dedupe` before `qa.py report` (or `qa.py next`).")
    gate = compute_gate(st, ctx.lanes)
    st["gate"] = gate
    finals = sorted(final_findings(st), key=sort_key)
    secs = {f["id"]: finding_sections(ctx, f) for f in finals}
    live = [f for f in finals if verdict_of(f) != "DISPUTED"]
    disputed = [f for f in finals if verdict_of(f) == "DISPUTED"]
    needs = [f for f in finals if verdict_of(f) == "NEEDS-ENV"]

    sev_counts = ", ".join("%s %d" % (s, sum(1 for f in live if f["severity"] == s)) for s in SEVERITIES)
    ver_counts = ", ".join("%s %d" % (v, sum(1 for f in finals if verdict_of(f) == v))
                            for v in ("CONFIRMED", "LIKELY", "LATENT", "NEEDS-ENV", "UNVERIFIED", "DISPUTED"))
    rejected = sum(1 for f in st["findings"].values() if f["status"] == "rejected")
    merged = sum(1 for f in st["findings"].values() if f["status"] == "merged")

    table = ["| ID | Severity | Lane(s) | Title | Verdict | Location |", "|---|---|---|---|---|---|"]
    for f in finals:
        table.append("| %s | %s | %s | %s%s | %s | `%s` |" % (
            f["id"], f["severity"], ", ".join(f["found_by_lanes"]), md_cell(f["title"]),
            " `multi-lane`" if f.get("multi_lane") else "", verdict_of(f), f["location"]))
    if not finals:
        table.append("| - | - | - | No findings | - | - |")

    blocks = []
    for sev in SEVERITIES:
        group = [f for f in live if f["severity"] == sev]
        if group:
            blocks.append("### %s (%d)\n" % (sev, len(group)))
            blocks += [render_finding(ctx, f, secs[f["id"]]) for f in group]
    findings_md = "\n".join(blocks) or "_No live findings._"

    disputed_md = "\n".join(
        "- **%s** %s · %s · `%s` (lanes: %s)\n  - Skeptic's evidence: %s%s" % (
            f["id"], f["severity"], md_cell(f["title"]), f["location"], ", ".join(f["found_by_lanes"]),
            one_line(f.get("verdict_evidence") or "(none)", 600),
            ("\n  - Reasoning: " + one_line(f["verdict_reason"], 600)) if f.get("verdict_reason") else "")
        for f in disputed) or "_No finding was disputed._"

    needs_md = "\n".join(
        "- **%s** %s · %s · `%s`\n  - What would settle it: %s" % (
            f["id"], f["severity"], md_cell(f["title"]), f["location"],
            one_line(f.get("verdict_needs") or f.get("verdict_note") or f.get("verdict_reason") or "(not stated)", 600))
        for f in needs) or "_Nothing is waiting on infrastructure._"

    rows = coverage(st, ctx.lanes)
    cov = ["| Lane | # | Checklist item | Examined by | Status |", "|---|---|---|---|---|"]
    for r in rows:
        status = "**NOT COVERED**" if r["status"] == "NOT COVERED" else r["status"]
        cov.append("| %s | %d | %s | %s | %s |" % (r["lane"], r["index"], md_cell(r["item"], 90),
                                                    ", ".join(r["by"]) or "-", status))
    run_rows = [r for r in rows if r["status"] != "skipped"]
    cov_summary = "%d of %d checklist items in the lanes that ran were examined. Lanes skipped: %s." % (
        sum(1 for r in run_rows if r["status"] == "covered"), len(run_rows),
        ", ".join(gate["gaps"]["skipped_lanes"]) or "none")
    if gate["gaps"]["failed_jobs"]:
        cov_summary += " Agents that never reported: %s." % ", ".join(gate["gaps"]["failed_jobs"])

    header = read_template("testcase.csv").strip().split(",")
    tc_rows = testcase_rows(ctx, finals, secs)
    tc = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for row in tc_rows:
        tc.append("| " + " | ".join(md_cell(c, 220) for c in row) + " |")
    if not tc_rows:
        tc.append("| " + " | ".join(["-"] * len(header)) + " |")

    flags = st.get("flags", {})
    flag_text = " ".join(x for x in (
        "--quick" if flags.get("quick") else "", "--no-verify" if flags.get("no_verify") else "",
        ("--lanes %s" % flags["lanes"]) if flags.get("lanes") else "",
        ("--skip %s" % flags["skip"]) if flags.get("skip") else "",
        ("--depth %s" % flags["depth"]) if flags.get("depth") else "",
        ("--seed %s" % st["seed"]) if st.get("seed") is not None else "",
        ("--rerun (of %s)" % flags["rerun_of"]) if flags.get("rerun_of") else "") if x) or "(defaults)"
    banner = ""
    if not st.get("verify", True):
        banner = ("> **UNVERIFIED RUN.** `--no-verify` skipped the skeptics. No finding below was independently "
                  "checked, and the gate cannot BLOCK on unverified findings.\n")

    values = {
        "target": md_cell(st.get("target") or st["run_id"]), "run_id": st["run_id"],
        "date": datetime.date.today().isoformat(), "stack": "%s (`%s`)" % (
            st["stack"].get("stack"), st["stack"].get("test_command")),
        "lanes": ", ".join(st["lanes"]), "flags": flag_text, "scope_sha": st["scope_sha256"],
        "version": VERSION, "unverified_banner": banner, "gate_result": gate["result"],
        "gate_reasons": "\n".join("- " + md_cell(r) for r in gate["reasons"]),
        "gate_gaps": "\n".join([
            "- Lanes skipped: %s" % (", ".join(gate["gaps"]["skipped_lanes"]) or "none"),
            "- Checklist items nobody examined: %d (see Coverage)" % len(gate["gaps"]["uncovered"]),
            "- NEEDS-ENV findings: %d" % len(gate["gaps"]["needs_env"]),
            "- Agents that never reported: %s" % (", ".join(gate["gaps"]["failed_jobs"]) or "none")]),
        "summary_counts": "Live findings by severity: %s  \nVerdicts: %s  \nRejected as malformed/vague: %d · "
                          "merged as duplicates: %d" % (sev_counts, ver_counts, rejected, merged),
        "summary_table": "\n".join(table), "findings": findings_md, "disputed": disputed_md,
        "needs_env": needs_md, "performance": performance_md(ctx),
        "coverage_summary": cov_summary, "coverage": "\n".join(cov),
        "testcases": "\n".join(tc), "tests_dir": ctx.rel("tests") + "/",
    }
    report = string.Template(read_template("report.md.tmpl")).safe_substitute(values)
    atomic_write(ctx.path("REPORT.md"), report)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(tc_rows)
    atomic_write(ctx.path("testcases.csv"), buf.getvalue().encode("utf-8-sig"))

    st["phase"] = "reported"
    ctx.save()

    out("REPORT: %s" % ctx.rel("REPORT.md"),
        "TESTCASES: %s" % ctx.rel("testcases.csv"),
        "GATE: %s" % gate["result"])
    for r in gate["reasons"][:8]:
        out("  - " + r)
    out("SEVERITY (live): " + sev_counts, "VERDICTS: " + ver_counts, "TOP:")
    for f in live[:5]:
        out("  %s %s %s%s: %s (%s)" % (f["id"], f["severity"], verdict_of(f),
                                        " multi-lane" if f.get("multi_lane") else "", f["title"], f["location"]))
    if not live:
        out("  (none)")
    print_gaps(gate["gaps"])
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--project", default=".", help="project root (default: current directory)")
    common.add_argument("--run", default=None, help="run id (default: .swarm-court/CURRENT)")
    common.add_argument("--json", action="store_true", help="machine-readable output where supported")

    lane_opts = argparse.ArgumentParser(add_help=False)
    lane_opts.add_argument("--lanes", help="comma-separated lanes or aliases (race, authz, queue, db, perf, ...)")
    lane_opts.add_argument("--skip", help="comma-separated lanes to exclude")
    lane_opts.add_argument("--quick", action="store_true", help="5 core lanes, depth 1")
    lane_opts.add_argument("--depth", type=int, help="hunters per lane (1-%d, default %d)" % (MAX_DEPTH, DEFAULT_DEPTH))
    lane_opts.add_argument("--no-verify", action="store_true", help="skip skeptics; findings are UNVERIFIED")
    lane_opts.add_argument("--wave", type=int, help="sub-agents per wave (default %d)" % DEFAULT_WAVE)

    p = argparse.ArgumentParser(prog="qa.py", description="swarm-court state machine (v%s)" % VERSION)
    sub = p.add_subparsers(dest="cmd")
    sub.required = True

    sp = sub.add_parser("plan", parents=[common, lane_opts], help="cost table; writes nothing")
    sp.add_argument("--est-findings", type=int, help="expected valid findings per hunter (default %d)"
                    % DEFAULT_EST_FINDINGS)
    sp.set_defaults(func=cmd_plan)

    sp = sub.add_parser("init", parents=[common, lane_opts], help="create a run from scope.md")
    sp.add_argument("--task-file", required=True)
    sp.add_argument("--seed")
    sp.add_argument("--target")
    sp.add_argument("--slug")
    sp.add_argument("--stack", help="override detected stack")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("next", parents=[common], help="print the single next action")
    sp.set_defaults(func=cmd_next)

    sp = sub.add_parser("prompts", parents=[common], help="write sub-agent briefs and print waves")
    sp.add_argument("kind", choices=("hunt", "verify"))
    sp.set_defaults(func=cmd_prompts)

    sp = sub.add_parser("validate", parents=[common], help="validate findings; move rejects")
    sp.add_argument("--force", action="store_true", help="validate even if hunters are still pending")
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("collect", parents=[common], help="record skeptic verdicts")
    sp.set_defaults(func=cmd_collect)

    sp = sub.add_parser("dedupe", parents=[common], help="merge same-root-cause findings")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_dedupe)

    for name, func, text in (("status", cmd_status, "progress overview"),
                             ("gate", cmd_gate, "compute the release gate"),
                             ("report", cmd_report, "write REPORT.md and testcases.csv"),
                             ("detect", cmd_detect, "detect the project stack")):
        sp = sub.add_parser(name, parents=[common], help=text)
        sp.set_defaults(func=func)

    sp = sub.add_parser("rerun", parents=[common], help="new run of one lane on the same scope")
    sp.add_argument("lane")
    sp.add_argument("--from", dest="source", help="run id to copy scope from (default: current)")
    sp.set_defaults(func=cmd_rerun)

    sp = sub.add_parser("mark", parents=[common], help="mark hunt jobs done when an agent replied but wrote no marker")
    sp.add_argument("kind", choices=("hunt",))
    sp.add_argument("ids", nargs="+")
    sp.set_defaults(func=cmd_mark)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except QAError as exc:
        print("qa.py: error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
