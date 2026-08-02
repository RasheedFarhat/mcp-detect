#!/usr/bin/env python3
"""Phase 6 -- framework/compiler.py: the five Wazuh-authoring gates.

Each gate corresponds to a real bug this project already hit and caught by
hand (docs/WAZUH-NOTES.md), plus one (gate 5) recommended after a real gap
was found the other four didn't cover. Two are static (structural
properties readable directly from rule XML text): gate 1 (if_sid
auto-parenting) and gate 3 (stock-ruleset collision grep). Three are
dynamic (properties that can only be observed by running the real engine
against a real fixture, per docs/PHASE6-DESIGN.md's corrected framing):
gate 2 (disjointness), gate 4 (negate-on-absent-field), and gate 5
(FP against the full benign corpus). Never a Python reimplementation of
rule matching -- the dynamic gates delegate to framework/structural.py's
real wazuh-logtest invocation.

Every violation raised here names the specific rule id, field name, and
mechanism involved -- never a generic "gate failed" message, so a future
false-pass can't hide behind a vacuous rejection.

CLI: `python3 framework/compiler.py validate --detection <path/to/detection.yaml>`
validates one candidate (need not be merged into detections/ yet) against
all five gates; `validate-all` does the same for the full registry. Gates
2, 4, and 5's fixtures are derived automatically from the candidate's own
`fixtures.attack_corpus` declaration (and, for chained detections,
`fixtures.canonical_derived_corpus`) via framework/fixtures.py's existing
grammar, reused, rather than a hand-maintained lookup table -- closing the
gap docs/PHASE6-T1105-REPORT.md named ("this test's fixture-gathering is
rule-specific by construction, not registry-driven"). Gate 2's automatic
check is reported as an informational tally, not a hard pass/fail: which
of a candidate's own fixtures land on its own rule id(s) versus a
deliberately-adjudicated overlap with another detection (SAF-T1105's
v01/v02 correctly deferring to 100101) is a human judgment call this
project's own experience says the gates validate, not make --
`docs/PHASE6-T1105-REPORT.md`'s Step 5 finding, applied here rather than
quietly contradicted by over-automating. Gate 5 (FP against the full
benign corpus) is itself the follow-through on that same report's own
recommendation, after the real 20/4727 search_files false positive slipped
past all four original gates and was only caught by a separate, ad hoc
measurement step.
"""
from __future__ import annotations

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from framework.schema import Detection  # noqa: E402
from framework.structural import preflight_wazuh_logtest, run_batch, verify_rule_sync  # noqa: E402

MANAGER_SERVICE = "wazuh.manager"
STOCK_RULESET_GLOB_CMD = "for f in /var/ossec/ruleset/rules/*.xml; do echo \"===FILE:$f===\"; cat \"$f\"; done"

# The two canonical parent anchors this migration's Detections chain under.
# A genuinely new record shape in a future phase would add a third entry
# here, not change the check's logic.
CONSUMES_TO_PARENT = {"raw_telemetry": "100100", "derived_record": "100200"}


@dataclass
class Violation:
    gate: str
    rule_id: str | None
    reason: str

    def __str__(self) -> str:
        rid = f"rule {self.rule_id}: " if self.rule_id else ""
        return f"[{self.gate}] {rid}{self.reason}"


# ---------------------------------------------------------------------------
# Shared XML rule parsing
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def _strip_comments(xml_text: str) -> str:
    """This project's own rule-authoring style uses ' -- ' as a prose
    separator throughout its XML comments (confirmed: wazuh/local_rules.xml
    itself), which contains a literal '--' -- invalid inside an XML comment
    per spec, though Wazuh's own rule-file parser tolerates it fine (the
    same kind of parser-leniency gap docs/WAZUH-NOTES.md constraint 4
    already found once, from the opposite direction). Python's stdlib
    ElementTree is spec-strict and rejects it. Comments carry no matching
    semantics, so stripping them before structural parsing changes nothing
    about what's being checked -- this is not a parsing hack of rule logic."""
    return _COMMENT_RE.sub("", xml_text)


def parse_rule_file(xml_text: str) -> dict[str, dict]:
    """Parse one Wazuh rule XML file's <rule> elements into
    {rule_id: {level, if_sid, field_names, negate_fields}}. Multiple <group>
    roots are not expected within one file (matches this project's own
    local_rules.xml shape); callers of parse_stock_ruleset() below parse
    each stock file independently for exactly this reason."""
    root = ET.fromstring(_strip_comments(xml_text))
    rules: dict[str, dict] = {}
    rule_iter = root.iter("rule") if root.tag != "rule" else [root]
    for rule_el in rule_iter:
        rid = rule_el.get("id")
        if rid is None:
            continue
        if_sid_el = rule_el.find("if_sid")
        if_sid = if_sid_el.text.strip() if if_sid_el is not None and if_sid_el.text else None
        field_names = set()
        negate_fields = set()
        for field_el in rule_el.findall("field"):
            name = field_el.get("name")
            if name:
                field_names.add(name)
                if field_el.get("negate") == "yes":
                    negate_fields.add(name)
        rules[rid] = {
            "level": rule_el.get("level"),
            "if_sid": if_sid,
            "field_names": field_names,
            "negate_fields": negate_fields,
        }
    return rules


def docker_compose(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", *args], cwd=REPO_ROOT,
                           capture_output=True, text=True, timeout=timeout)


def fetch_stock_ruleset() -> dict[str, dict[str, dict]]:
    """{file_path: {rule_id: {...}}} for every *.xml under
    /var/ossec/ruleset/rules/ on the live manager -- the FULL shipped
    ruleset, not just this project's own files, per docs/WAZUH-NOTES.md
    constraint 8's standing rule."""
    proc = docker_compose("exec", "-T", MANAGER_SERVICE, "sh", "-c", STOCK_RULESET_GLOB_CMD)
    if proc.returncode != 0:
        raise RuntimeError(f"could not fetch stock ruleset: {proc.stderr}")
    result: dict[str, dict[str, dict]] = {}
    chunks = proc.stdout.split("===FILE:")[1:]
    for chunk in chunks:
        path, _, xml_text = chunk.partition("===\n")
        path = path.strip()
        try:
            result[path] = parse_rule_file(xml_text)
        except ET.ParseError:
            # A handful of stock files aren't well-formed as a single root
            # element on their own (rare, e.g. macro/include-only files) --
            # skip parsing failures rather than crash the whole fetch; this
            # is a collision *grep*, not an exhaustive validator, matching
            # WAZUH-NOTES.md's own audit methodology (constraint 4's audit
            # was also a grep, not a full parse).
            continue
    return result


# ---------------------------------------------------------------------------
# Gate 1 -- if_sid auto-parenting (static: read directly from rule XML)
# ---------------------------------------------------------------------------

def gate1_if_sid_parenting(detections: list[Detection], rule_file_text: str) -> list[Violation]:
    """Refuses an independent top-level wazuh_rule detection. Every
    wazuh_rule backend entry must declare a parent_rule consistent with its
    consumes value, and the ACTUAL rule XML must chain via <if_sid> to that
    exact parent -- not just the schema's say-so."""
    rules = parse_rule_file(rule_file_text)
    violations: list[Violation] = []
    for d in detections:
        for entry in d.backends:
            if entry.backend != "wazuh_rule":
                continue
            expected_parent = CONSUMES_TO_PARENT.get(entry.consumes)
            if entry.parent_rule is None:
                violations.append(Violation(
                    "gate1_if_sid_parenting", None,
                    f"{d.name}: wazuh_rule entry (consumes={entry.consumes!r}) declares no "
                    f"parent_rule -- refusing to register an independent top-level detection"
                ))
                continue
            if expected_parent and entry.parent_rule != expected_parent:
                violations.append(Violation(
                    "gate1_if_sid_parenting", None,
                    f"{d.name}: consumes={entry.consumes!r} must chain under canonical parent "
                    f"{expected_parent!r}, but declares parent_rule={entry.parent_rule!r}"
                ))
            for rid in entry.logic_ref.wazuh_rule_ids:
                rule = rules.get(rid)
                if rule is None:
                    violations.append(Violation(
                        "gate1_if_sid_parenting", rid,
                        f"{d.name}: declared in logic_ref but not found in "
                        f"{entry.logic_ref.rule_file}"
                    ))
                    continue
                if rule["if_sid"] is None:
                    violations.append(Violation(
                        "gate1_if_sid_parenting", rid,
                        f"{d.name}: has no <if_sid> in the actual rule XML -- an independent "
                        f"top-level rule, the exact sibling-shadowing class "
                        f"docs/WAZUH-NOTES.md Tests 1-5 proved is unsafe"
                    ))
                elif rule["if_sid"] != entry.parent_rule:
                    violations.append(Violation(
                        "gate1_if_sid_parenting", rid,
                        f"{d.name}: actual <if_sid>{rule['if_sid']}</if_sid> in the XML doesn't "
                        f"match declared parent_rule={entry.parent_rule!r}"
                    ))
    return violations


# ---------------------------------------------------------------------------
# Gate 3 -- stock-ruleset collision grep (static: text/field-name comparison)
# ---------------------------------------------------------------------------

def check_stock_collision(candidate_field_names: set[str], stock_ruleset: dict[str, dict[str, dict]],
                           *, candidate_label: str) -> list[Violation]:
    """A collision exists when some stock rule's own required field-name
    set is a SUBSET of (or equal to) the candidate's -- meaning any record
    satisfying the candidate's field-presence requirements would also
    satisfy that stock rule's, the exact mechanism that let Suricata's
    86600 (requires {timestamp, event_type}) intercept 100200's first
    draft. Reproduces docs/WAZUH-NOTES.md constraint 8's standing rule:
    grep the ENTIRE loaded ruleset, not just this project's own files."""
    violations = []
    for path, rules in stock_ruleset.items():
        for rid, rule in rules.items():
            stock_fields = rule["field_names"]
            if stock_fields and stock_fields.issubset(candidate_field_names):
                violations.append(Violation(
                    "gate3_stock_collision", candidate_label,
                    f"collides with stock rule {rid} in {path} -- that rule requires fields "
                    f"{sorted(stock_fields)}, all of which the candidate's own record also "
                    f"carries ({sorted(candidate_field_names)}); first-match-wins evaluation "
                    f"order is undocumented, so this rule could silently shadow the candidate"
                ))
    return violations


# ---------------------------------------------------------------------------
# Gate 2 -- disjointness (dynamic: real wazuh-logtest)
# ---------------------------------------------------------------------------

def gate2_disjointness(fixture_lines: list[str], expected_rule_ids: list[str | None]) -> list[Violation]:
    """Runs `fixture_lines` through the real, currently-loaded ruleset via
    wazuh-logtest and fails loud unless each record's final matched rule id
    is the expected one. Checking the FINAL matched id (not merely "did
    rule X get tried") satisfies both halves of docs/WAZUH-NOTES.md's
    sharper standing rule in one pass: a match against the expected id
    proves both that the target rule fired AND that nothing else
    intercepted the event first, since wazuh-logtest reports exactly one
    final matched rule per record."""
    actual = run_batch(fixture_lines)
    violations = []
    for i, (line, expected, got) in enumerate(zip(fixture_lines, expected_rule_ids, actual)):
        if got != expected:
            violations.append(Violation(
                "gate2_disjointness", got,
                f"record {i}: expected final matched rule {expected!r}, got {got!r} -- "
                f"record={line[:200]}"
            ))
    return violations


# ---------------------------------------------------------------------------
# Gate 4 -- negate-on-absent-field probe (dynamic: real wazuh-logtest, NOT static)
# ---------------------------------------------------------------------------

def gate4_negate_probe(detections: list[Detection], rule_file_text: str,
                        true_positive_fixtures: dict[str, str]) -> list[Violation]:
    """For every wazuh_rule whose actual XML uses negate="yes" on a field,
    run ITS OWN registered true-positive fixture (a record that should
    trigger it) through real wazuh-logtest and confirm the final matched
    rule id is that rule itself -- not the no-alert parent. This is folded
    into gate 2's exact fixture-execution machinery (same run_batch call),
    not a separate mechanism, per docs/PHASE6-DESIGN.md's corrected
    framing: this behavior cannot be determined by reading the XML or the
    fixture's JSON shape -- it is a property of Wazuh's negate evaluator,
    observable only by running the real engine."""
    rules = parse_rule_file(rule_file_text)
    violations = []
    for d in detections:
        for entry in d.backends:
            if entry.backend != "wazuh_rule":
                continue
            for rid in entry.logic_ref.wazuh_rule_ids:
                rule = rules.get(rid)
                if rule is None or not rule["negate_fields"]:
                    continue
                fixture_line = true_positive_fixtures.get(rid)
                if fixture_line is None:
                    violations.append(Violation(
                        "gate4_negate_probe", rid,
                        f"{d.name}: uses negate={sorted(rule['negate_fields'])} but no "
                        f"true-positive fixture registered to probe it against -- status "
                        f"cannot advance past 'proposed' without one"
                    ))
                    continue
                matched = run_batch([fixture_line])
                if matched[0] != rid:
                    violations.append(Violation(
                        "gate4_negate_probe", rid,
                        f"{d.name}: negate={sorted(rule['negate_fields'])} does not fire on its "
                        f"own true-positive fixture -- final matched rule was {matched[0]!r}, "
                        f"not {rid!r}. This is the negate-on-absent-field landmine "
                        f"(docs/PHASE3A-DESIGN.md:470-478, docs/PHASE5-REPORT.md:24): negating "
                        f"on a field that is genuinely absent from the record does not satisfy "
                        f"the condition in this Wazuh version."
                    ))
    return violations


# ---------------------------------------------------------------------------
# Gate 5 -- FP against the full benign corpus (dynamic: real wazuh-logtest)
# ---------------------------------------------------------------------------

def run_benign_corpus() -> list[tuple[str, str | None]]:
    """(record_line, final_matched_rule_id) pairs for the full, frozen,
    committed benign corpus (a static repo file, unlike the live-fetched
    attack corpora -- no docker/agent dependency to read it, though running
    it through wazuh-logtest still needs the live manager)."""
    benign_path = REPO_ROOT / "data" / "benign_corpus_v2.jsonl"
    lines = [l for l in benign_path.read_text().splitlines() if l.strip()]
    matched = run_batch(lines)
    return list(zip(lines, matched))


def gate5_benign_fp(detection: Detection, benign_pairs: list[tuple[str, str | None]]) -> list[Violation]:
    """Refuses to certify a detection whose own rule id(s) fire on ANY
    record in the full benign corpus. Recommended in
    docs/PHASE6-T1105-REPORT.md after the real 20/4727 search_files false
    positive was caught by a separate, ad hoc measurement step -- not by
    any of gates 1-4 -- during SAF-T1105's own build: "a detection could
    pass all four write-side gates cleanly and still carry an undiscovered
    FP problem." This is that fifth gate, built."""
    own_ids = set(detection.all_wazuh_rule_ids())
    violations = []
    for line, matched in benign_pairs:
        if matched in own_ids:
            violations.append(Violation(
                "gate5_benign_fp", matched,
                f"{detection.name}: fires on a benign corpus record -- record={line[:200]}"
            ))
    return violations


# ---------------------------------------------------------------------------
# Fixture derivation -- resolve a Detection's OWN declared attack_corpus into
# real fixture lines, so gates 2/4 don't need a hand-maintained per-rule
# lookup table (docs/PHASE6-T1105-REPORT.md named this as a real marginal
# cost slice 3 had to pay by hand in test_compiler_regression.py).
# ---------------------------------------------------------------------------

TELEMETRY_PATH_IN_CONTAINER = "/var/log/mcp-detect/telemetry.jsonl"
RUGPULL_ALERTS_PATH_IN_CONTAINER = "/var/log/mcp-detect/rugpull_alerts.jsonl"
AGENT_SERVICE = "agent"


def run_attack_corpus(detection: Detection) -> list[tuple[str, str | None]]:
    """(fixture_line, final_matched_rule_id) pairs for this detection's own
    attack fixtures, resolved via framework/fixtures.py's existing grammar
    and run through the real engine -- never a hardcoded lookup.

    A chained detection's final (structural) stage matches on a DERIVED
    record, not raw telemetry (rug pull: 100201 only ever matches
    baseline/watch.py's output, never a raw tools/call) -- for those, use
    the already-computed `canonical_derived_corpus` fixture instead of
    `attack_corpus`, exactly the same distinction
    docs/PHASE6-MIGRATION-REPORT.md's disclosed judgment call #4 already
    made for framework/coverage.py's canonical-corpus handling. Feeding raw
    telemetry to a rule that only matches derived records would silently
    report every fixture as a miss -- confirmed by hitting exactly that
    bug during this function's own first version."""
    from framework.fixtures import parse_live_telemetry_ref, filter_records
    from framework.structural import fetch_container_file

    consumes_derived = any(entry.consumes == "derived_record" for entry in detection.backends)
    if consumes_derived:
        derived_ref = detection.fixtures.get("canonical_derived_corpus", "")
        if derived_ref != "live:rugpull_alerts":
            return []
        text = fetch_container_file(AGENT_SERVICE, RUGPULL_ALERTS_PATH_IN_CONTAINER)
        fixtures = [l for l in text.splitlines() if l.strip()]
    else:
        ref = detection.fixtures.get("attack_corpus", "")
        if not ref.startswith("live:telemetry#"):
            return []
        params = parse_live_telemetry_ref(ref)
        text = fetch_container_file(AGENT_SERVICE, TELEMETRY_PATH_IN_CONTAINER)
        lines = [l for l in text.splitlines() if l.strip()]
        fixtures = filter_records(lines, **params)

    if not fixtures:
        return []
    matched = run_batch(fixtures)
    return list(zip(fixtures, matched))


def tally_disjointness(detection: Detection, pairs: list[tuple[str, str | None]]) -> dict:
    """Tallies where a detection's own attack-corpus fixtures actually land:
    its own rule id(s), a deliberately-adjudicated overlap with some other
    rule, or nothing at all (100100/100200, the no-alert parents -- a
    genuine miss). Reported as information, not an automatic hard pass/fail
    -- see module docstring."""
    own_ids = set(detection.all_wazuh_rule_ids())
    own_hits = sum(1 for _, m in pairs if m in own_ids)
    no_match = sum(1 for _, m in pairs if m in (None, "100100", "100200"))
    deferred: dict[str, int] = {}
    for _, m in pairs:
        if m not in own_ids and m not in (None, "100100", "100200"):
            deferred[m] = deferred.get(m, 0) + 1
    return {"total": len(pairs), "own_hits": own_hits, "no_match": no_match, "deferred": deferred}


def find_fixture_for_rule(pairs: list[tuple[str, str | None]], rule_id: str) -> str | None:
    for line, matched in pairs:
        if matched == rule_id:
            return line
    return None


# ---------------------------------------------------------------------------
# Registry-wide rule-id collision check -- reuses framework/alerts.py's
# existing rule_id_to_detection(), previously only ever invoked deep inside
# coverage.py's pipeline run. Wiring it in here catches a collision between
# two independently-authored detections immediately, at compile time.
# ---------------------------------------------------------------------------

def check_rule_id_collisions(detections: list[Detection]) -> list[Violation]:
    from framework.alerts import rule_id_to_detection
    try:
        rule_id_to_detection(detections)
    except ValueError as e:
        return [Violation("registry_collision", None, str(e))]
    return []


# ---------------------------------------------------------------------------
# Orchestration -- validate one Detection against all applicable gates, or
# the whole registry at once. This is the real "compile a detection" logic;
# framework/tests/test_compiler_regression.py calls into this rather than
# hand-rolling its own copy.
# ---------------------------------------------------------------------------

@dataclass
class DetectionReport:
    name: str
    gate1: list[Violation]
    gate3: list[Violation]
    disjointness_tally: dict
    gate4: list[Violation]
    gate4_unprobed: list[str]
    gate5: list[Violation]
    status: str = ""
    status_violations: list[Violation] = None  # type: ignore[assignment]
    promotable: bool = False

    def __post_init__(self) -> None:
        if self.status_violations is None:
            self.status_violations = []

    def is_clean(self) -> bool:
        # Scenario corpora include setup/teardown records and deliberate
        # overlaps, so no-match/deferred counts are not per-record failures
        # without labelled expected rule ids.  The current metadata can
        # still prove that a non-empty corpus ran and reached this
        # detection's own rules at least once.  Exact per-record checks use
        # gate2_disjointness(), whose caller supplies the expected ids.
        disjointness_failed = (
            not self.disjointness_tally.get("total")
            or not self.disjointness_tally.get("own_hits")
        )
        return not (
            self.gate1 or self.gate3 or disjointness_failed or self.gate4
            or self.gate4_unprobed or self.gate5 or self.status_violations
        )


def validate_detection(detection: Detection, rule_file_text: str, *, skip_live: bool = False,
                        benign_pairs: list[tuple[str, str | None]] | None = None) -> DetectionReport:
    gate1 = gate1_if_sid_parenting([detection], rule_file_text)

    rules = parse_rule_file(rule_file_text)
    gate3: list[Violation] = []
    tally = {"total": 0, "own_hits": 0, "no_match": 0, "deferred": {}}
    gate4: list[Violation] = []
    gate4_unprobed: list[str] = []
    gate5: list[Violation] = []

    if not skip_live:
        # Gate 3 only applies to a rule that is itself top-level (no
        # <if_sid> in the actual XML) -- a child rule can never collide
        # with a stock top-level rule the way a new canonical parent could.
        top_level_ids = [rid for rid in detection.all_wazuh_rule_ids()
                         if rid in rules and rules[rid]["if_sid"] is None]
        if top_level_ids:
            stock = fetch_stock_ruleset()
            for rid in top_level_ids:
                gate3 += check_stock_collision(rules[rid]["field_names"], stock, candidate_label=rid)

        pairs = run_attack_corpus(detection)
        tally = tally_disjointness(detection, pairs)
        # Build the COMPLETE {rid: fixture} map before calling
        # gate4_negate_probe -- it iterates every negate-using rule id
        # across the detection's own backends on each call, so calling it
        # once per rid with a partial map produces spurious "no fixture
        # registered" violations for every OTHER rid not yet in that map
        # (confirmed by hitting exactly this bug against credential_exfil's
        # 5-rule-id exfil_hop entry during this function's own first
        # version -- one real call with the full map, not five partial ones).
        fixtures_for_gate4: dict[str, str] = {}
        for rid in detection.all_wazuh_rule_ids():
            rule = rules.get(rid)
            if not rule or not rule["negate_fields"]:
                continue
            fixture = find_fixture_for_rule(pairs, rid)
            if fixture is None:
                gate4_unprobed.append(rid)
            else:
                fixtures_for_gate4[rid] = fixture
        if fixtures_for_gate4:
            gate4 = gate4_negate_probe([detection], rule_file_text, fixtures_for_gate4)

        if benign_pairs is None:
            benign_pairs = run_benign_corpus()
        gate5 = gate5_benign_fp(detection, benign_pairs)

    # Status consistency -- only meaningful when the dynamic gates actually
    # ran (skip_live=True leaves gate3/4/5 empty by construction, not
    # because they passed, so claiming status consistency in that mode
    # would be asserting something never actually checked).
    status_violations: list[Violation] = []
    promotable = False
    if not skip_live:
        disjointness_failed = not tally["total"] or not tally["own_hits"]
        gates_clean = not (gate1 or gate3 or disjointness_failed or gate4
                           or gate4_unprobed or gate5)
        if detection.status in ("validated", "deployed") and not gates_clean:
            status_violations.append(Violation(
                "status_consistency", None,
                f"{detection.name}: status={detection.status!r} but does not currently pass all "
                f"five gates (see violations above) -- status stops being cosmetic the moment "
                f"something checks it: a detection claiming 'validated'/'deployed' must actually "
                f"validate against the current ruleset and corpora, not just have once."
            ))
        promotable = detection.status == "proposed" and gates_clean

    return DetectionReport(detection.name, gate1, gate3, tally, gate4, gate4_unprobed, gate5,
                            status=detection.status, status_violations=status_violations,
                            promotable=promotable)


def validate_registry(detections_dir: Path | None = None, *, rule_file: Path | None = None,
                       skip_live: bool = False) -> tuple[list[DetectionReport], list[Violation]]:
    """Runs every registered Detection through validate_detection() and
    checks for registry-wide rule-id collisions. The real orchestration
    logic for "does the whole registry compile cleanly" -- moved here from
    being embedded inside framework/tests/test_compiler_regression.py, so
    it's a reusable tool, not test-only logic (test files should test the
    tool, not be the tool)."""
    from framework.registry import load_registry
    detections = load_registry(detections_dir) if detections_dir else load_registry()
    rule_file_text = (rule_file or (REPO_ROOT / "wazuh" / "local_rules.xml")).read_text()
    # Fetch the benign corpus and run it through wazuh-logtest exactly ONCE,
    # shared across every detection -- 4727 records is expensive enough
    # that re-running it per detection would make validate-all needlessly
    # slow as the registry grows.
    if skip_live:
        benign_pairs = None
    else:
        # Deployment provenance and direct-engine readiness are separate from
        # rule correctness. Fail before the expensive corpus sweep if the live
        # file is stale or logtest cannot return one complete probe result.
        verify_rule_sync()
        preflight_wazuh_logtest()
        benign_pairs = run_benign_corpus()
    reports = [validate_detection(d, rule_file_text, skip_live=skip_live, benign_pairs=benign_pairs)
               for d in detections]
    collisions = check_rule_id_collisions(detections)
    return reports, collisions


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_report(report: DetectionReport) -> bool:
    print(f"\n=== {report.name} ===")
    print(f"Gate 1 (if_sid auto-parenting): {len(report.gate1)} violation(s)")
    for v in report.gate1:
        print(f"  {v}")
    print(f"Gate 3 (stock-ruleset collision): {len(report.gate3)} violation(s)")
    for v in report.gate3:
        print(f"  {v}")
    t = report.disjointness_tally
    print(f"Gate 2 (disjointness tally against this detection's own attack_corpus): "
          f"{t['own_hits']}/{t['total']} own-rule hits, {t['no_match']} no-match, "
          f"deferred={t['deferred']}")
    if not t["total"] or not t["own_hits"]:
        print("  VIOLATION: no executable evidence hit this detection's own rule id; "
              "clean compiler status is blocked")
    elif t["no_match"] or t["deferred"]:
        print("  INFO: scenario records without own-rule hits require the documented human "
              "overlap/miss adjudication; fixtures do not label expected ids per record")
    print(f"Gate 4 (negate-on-absent-field probe): {len(report.gate4)} violation(s)")
    for v in report.gate4:
        print(f"  {v}")
    if report.gate4_unprobed:
        print(f"  VIOLATION: negate-using rule(s) with no fixture available to probe: "
              f"{report.gate4_unprobed}")
    print(f"Gate 5 (FP against benign corpus): {len(report.gate5)} violation(s)")
    for v in report.gate5[:10]:
        print(f"  {v}")
    if len(report.gate5) > 10:
        print(f"  ... and {len(report.gate5) - 10} more")
    if report.status_violations or report.promotable:
        print(f"Status (declared: {report.status!r}):")
        for v in report.status_violations:
            print(f"  {v}")
        if report.promotable:
            print(f"  INFO: status={report.status!r} but all five gates currently pass cleanly -- "
                  f"a candidate for promotion")
    return report.is_clean()


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="validate one candidate detection.yaml")
    p_validate.add_argument("--detection", required=True,
                             help="path to a detection.yaml (need not be under detections/ yet)")
    p_validate.add_argument("--rule-file", default=str(REPO_ROOT / "wazuh" / "local_rules.xml"))
    p_validate.add_argument("--skip-live", action="store_true",
                             help="skip gates that need docker/wazuh-logtest (gate 3, gate 2 tally, gate 4)")

    p_all = sub.add_parser("validate-all", help="validate the full registry")
    p_all.add_argument("--rule-file", default=str(REPO_ROOT / "wazuh" / "local_rules.xml"))
    p_all.add_argument("--skip-live", action="store_true")

    args = parser.parse_args()

    if args.command == "validate":
        from framework.schema import load_detection_file
        from framework.registry import load_registry

        candidate = load_detection_file(Path(args.detection))
        try:
            existing = load_registry()
        except RuntimeError:
            existing = []
        all_detections = existing if candidate.name in {d.name for d in existing} else existing + [candidate]

        rule_file_text = Path(args.rule_file).read_text()
        report = validate_detection(candidate, rule_file_text, skip_live=args.skip_live)
        clean = _print_report(report)
        collisions = check_rule_id_collisions(all_detections)
        for v in collisions:
            print(f"\nREGISTRY: {v}")
        ok = clean and not collisions
        print(f"\n{'CLEAN' if ok else 'VIOLATIONS FOUND'}")
        return 0 if ok else 1

    if args.command == "validate-all":
        reports, collisions = validate_registry(rule_file=Path(args.rule_file), skip_live=args.skip_live)
        all_clean = True
        for r in reports:
            all_clean &= _print_report(r)
        for v in collisions:
            print(f"\nREGISTRY: {v}")
        all_clean = all_clean and not collisions
        print(f"\n{'ALL CLEAN' if all_clean else 'VIOLATIONS FOUND'} -- {len(reports)} detection(s) checked")
        return 0 if all_clean else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
