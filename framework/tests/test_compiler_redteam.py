#!/usr/bin/env python3
"""Red-team proof harness for framework/compiler.py's five gates.

Each gate is proven against a reconstruction of the specific historical bug
it exists to catch -- not asserted, run. Gates 1 and 3 are static (no
container interaction). Gates 2, 4, and 5 are dynamic: their red-team fixture
XML (framework/tests/redteam_fixtures/*.xml) is installed transiently into
the live manager's /var/ossec/etc/rules/ directory via `docker compose cp`
-- the same "iterate via wazuh-logtest, never restart the manager for a
hypothesis" standing process rule docs/WAZUH-NOTES.md already established
-- proven, then removed via `docker compose exec ... rm` in a `finally`
block. wazuh/local_rules.xml is never touched; verified byte-identical
before and after every dynamic proof, not just at the end.

Run: python3 framework/tests/test_compiler_redteam.py
(Requires the .venv interpreter on this host -- see docs/PHASE6-COMPILER-REPORT.md
for why: the system Python 3.14's pyexpat binding is broken in this
environment, unrelated to this project's code.)
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "lab" / "analysis"))

import report as report_mod  # noqa: E402
from framework.registry import load_registry  # noqa: E402
from framework.schema import Detection, BackendEntry, LogicRef, SessionKey  # noqa: E402
from framework.compiler import (  # noqa: E402
    gate1_if_sid_parenting, gate2_disjointness, gate4_negate_probe, gate5_benign_fp,
    fetch_stock_ruleset, check_stock_collision, docker_compose, MANAGER_SERVICE,
)
from framework.structural import run_batch  # noqa: E402

FIXTURES_DIR = Path(__file__).parent / "redteam_fixtures"
LOCAL_RULES = REPO_ROOT / "wazuh" / "local_rules.xml"
CONTAINER_RULES_DIR = "/var/ossec/etc/rules"

results: list[tuple[str, bool, str]] = []


def record(gate: str, ok: bool, detail: str) -> None:
    results.append((gate, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'} -- {gate}: {detail}")


_LOCAL_RULES_SNAPSHOT_AT_START = LOCAL_RULES.read_bytes()


def confirm_local_rules_untouched() -> None:
    """Checks the file hasn't changed DURING this test run -- a snapshot
    comparison, not `git diff --exit-code` against HEAD. Slice 2 could use
    the git-diff form safely because wazuh/local_rules.xml had zero
    uncommitted changes at the time; slice 3 legitimately adds a new rule
    to that same file before this test ever runs, so "differs from HEAD"
    is no longer equivalent to "this test just mutated it." Comparing
    against a snapshot taken at import time is correct in both cases."""
    current = LOCAL_RULES.read_bytes()
    if current != _LOCAL_RULES_SNAPSHOT_AT_START:
        raise RuntimeError("wazuh/local_rules.xml changed during this test run -- STOP")


def install_temp_rule(local_fixture_path: Path, container_filename: str) -> None:
    proc = docker_compose("cp", str(local_fixture_path), f"{MANAGER_SERVICE}:{CONTAINER_RULES_DIR}/{container_filename}")
    if proc.returncode != 0:
        raise RuntimeError(f"could not install temp rule file: {proc.stderr}")


def remove_temp_rule(container_filename: str) -> None:
    proc = docker_compose("exec", "-T", MANAGER_SERVICE, "rm", "-f", f"{CONTAINER_RULES_DIR}/{container_filename}")
    if proc.returncode != 0:
        raise RuntimeError(f"could not remove temp rule file: {proc.stderr}")
    # confirm removal, not just trust the exit code
    proc2 = docker_compose("exec", "-T", MANAGER_SERVICE, "test", "-f", f"{CONTAINER_RULES_DIR}/{container_filename}")
    if proc2.returncode == 0:
        raise RuntimeError(f"temp rule file {container_filename} still present after rm -- STOP")


# ---------------------------------------------------------------------------
# Gate 1 red-team proof -- the sibling-shadowing class (static, in-memory)
# ---------------------------------------------------------------------------

def prove_gate1() -> None:
    redteam_rule_xml = """<group name="mcp_detect_redteam,">
  <rule id="100193" level="12">
    <decoded_as>json</decoded_as>
    <field name="session_id" type="pcre2">.+</field>
    <field name="method" type="pcre2">^tools/call$</field>
    <description>REDTEAM GATE1 FIXTURE -- independent top-level rule, no if_sid</description>
  </rule>
</group>"""
    redteam_detection = Detection(
        technique_id="SAF-T9999", name="redteam_parentless_top_level",
        detection_type="structural", status="proposed",
        mitre_attack_ids=[], mitre_atlas_ids=[], description="red-team gate1 fixture",
        backends=[BackendEntry(
            backend="wazuh_rule",
            logic_ref=LogicRef(wazuh_rule_ids=["100193"], rule_file="framework/tests/redteam_fixtures/gate1"),
            consumes="raw_telemetry", parent_rule="100100",
        )],
        expected_signal={}, session_key=SessionKey(primary_field="session_id"),
        fixtures={}, known_gaps=[],
    )
    violations = gate1_if_sid_parenting([redteam_detection], redteam_rule_xml)
    caught = any(v.rule_id == "100193" and "no <if_sid>" in v.reason for v in violations)
    record("gate1_if_sid_parenting", caught,
           f"reconstructed WAZUH-NOTES.md Tests 1-5's parentless top-level rule -- "
           f"{'refused with a specific diagnostic' if caught else 'NOT CAUGHT'}: "
           + ("; ".join(str(v) for v in violations) if violations else "no violations raised"))


# ---------------------------------------------------------------------------
# Gate 3 red-team proof -- the Suricata 86600 collision (static, live ruleset)
# ---------------------------------------------------------------------------

def prove_gate3() -> None:
    stock = fetch_stock_ruleset()
    # lab/baseline/watch.py's ORIGINAL drift-marker field, before the rename to
    # mcp_drift_marker (wazuh/local_rules.xml:298-312's own history comment)
    original_draft_fields = {"timestamp", "event_type"}
    violations = check_stock_collision(original_draft_fields, stock, candidate_label="100200_original_draft")
    caught = any("86600" in v.reason for v in violations)
    record("gate3_stock_collision", caught,
           f"reconstructed the pre-rename 100200 draft (fields={sorted(original_draft_fields)}) -- "
           + ("collision with 86600 correctly flagged: " + violations[0].reason if caught
              else "NOT CAUGHT: " + ("; ".join(str(v) for v in violations) if violations else "no violations raised")))


# ---------------------------------------------------------------------------
# Gate 2 red-team proof -- non-disjoint duplicate rule (dynamic)
# ---------------------------------------------------------------------------

def prove_gate2() -> None:
    """The historical risk gate 2 protects against is not "does the new
    rule always lose" (docs/WAZUH-NOTES.md Test 4 already found ordering
    isn't something rule authoring controls, in either direction) -- it's
    "a new detection's author silently assumes their own rule fires on its
    own true positive, when an already-loaded, non-disjoint sibling
    actually wins the race instead." That is exactly what's checked here:
    register the red-team rule's OWN naive expectation (that IT, 100191,
    would be the final match on a record satisfying its conditions) and
    confirm gate2 flags the gap between that assumption and the real
    engine's actual behavior -- the same false assumption 3a's own
    disjointness work (wazuh/local_rules.xml:65-84's history comment) had
    to discover and design around, not accept."""
    confirm_local_rules_untouched()
    fixture_file = FIXTURES_DIR / "gate2_duplicate_of_100101.xml"
    container_name = "zz_redteam_gate2.xml"

    telemetry = report_mod.fetch_container_file("agent", "/var/log/mcp-detect/telemetry.jsonl")
    lines = [l for l in telemetry.splitlines() if l.strip()]
    malicious = [l for l in lines if json.loads(l).get("label") == "malicious"]
    fixture_100101 = next(
        l for l in malicious
        if json.loads(l).get("tool_name") == "read_text_file"
        and json.loads(l).get("task_id") == "attack_credential_exfil_sandbox_bait"
    )

    install_temp_rule(fixture_file, container_name)
    try:
        # Direction A: does the pre-existing 100101 keep winning? (informative,
        # not the headline claim -- WAZUH-NOTES Test 4 already showed load
        # order isn't controllable, so this could go either way run to run.)
        actual = gate2_disjointness([fixture_100101], ["100101"])
        winner_is_100101 = not actual

        # Direction B (the headline proof): a new detection's author
        # registering 100191 with this SAME fixture as its own true positive
        # would naively expect final matched rule == 100191. Confirm gate2
        # catches that this naive expectation is FALSE -- the mere presence
        # of a violation here is the whole proof.
        naive_violation = gate2_disjointness([fixture_100101], ["100191"])
        caught = bool(naive_violation)
        detail = (
            f"actual final match on the shared fixture: "
            f"{'100101 (pre-existing sibling)' if winner_is_100101 else 'something else -- ' + str(actual)}. "
            f"A new-detection author naively registering 100191 (identical conditions to 100101) "
            f"expecting IT to be the final match would be wrong -- gate2 catches exactly that gap: "
            + (naive_violation[0].reason if naive_violation else "NOT CAUGHT -- gate2 agreed with the naive expectation")
        )
        record("gate2_disjointness", caught, detail)
    finally:
        remove_temp_rule(container_name)
        confirm_local_rules_untouched()


# ---------------------------------------------------------------------------
# Gate 4 red-team proof -- 100103's original broken negate draft (dynamic)
# ---------------------------------------------------------------------------

def prove_gate4() -> None:
    """The true positive must be isolated from the REAL, corrected 100103
    (which stays loaded throughout -- wazuh/local_rules.xml is never
    touched), or a pass could mean either "the negate bug was caught" or
    merely "the real 100103 won the sibling race regardless," which would
    prove nothing about 100192's own negate behavior specifically. Any
    record with tool_arguments.data secret-shaped content and a tool_name
    NOT on the real rule's negate-exclusion list would also trip the real
    100103 -- so this fixture deliberately uses tool_name="read_text_file"
    (one of the real rule's own excluded read-tool names,
    wazuh/local_rules.xml:89), which makes the REAL 100103 correctly stay
    silent, isolating 100192 (whose negate is on tool_arguments.path, not
    tool_name) as the only rule that could possibly fire on this record."""
    confirm_local_rules_untouched()
    fixture_file = FIXTURES_DIR / "gate4_original_broken_negate_100103.xml"
    container_name = "zz_redteam_gate4.xml"

    true_positive = json.dumps({
        "session_id": "redteam-gate4-isolated", "timestamp": "2026-07-10T00:00:00Z",
        "method": "tools/call", "tool_name": "read_text_file",
        "server_command": "python3 lab/attacks/servers/exfil_sink_server.py",
        "tool_arguments": {"data": "postgres://evil:evil@host/db"},
        "scenario_id": "redteam", "task_id": "redteam_gate4_isolated", "label": "malicious",
    })

    redteam_detection = Detection(
        technique_id="SAF-T9998", name="redteam_original_broken_negate",
        detection_type="structural", status="proposed",
        mitre_attack_ids=[], mitre_atlas_ids=[], description="red-team gate4 fixture",
        backends=[BackendEntry(
            backend="wazuh_rule",
            logic_ref=LogicRef(wazuh_rule_ids=["100192"], rule_file="framework/tests/redteam_fixtures/gate4"),
            consumes="raw_telemetry", parent_rule="100100",
        )],
        expected_signal={}, session_key=SessionKey(primary_field="session_id"),
        fixtures={}, known_gaps=[],
    )
    rule_xml_text = fixture_file.read_text()

    install_temp_rule(fixture_file, container_name)
    try:
        violations = gate4_negate_probe([redteam_detection], rule_xml_text, {"100192": true_positive})
        caught = any(v.rule_id == "100192" for v in violations)
        record("gate4_negate_probe", caught,
               f"reconstructed 100103's original tool_arguments.path-absence negate draft -- "
               + (violations[0].reason if caught else "NOT CAUGHT: fixture unexpectedly fired"))
    finally:
        remove_temp_rule(container_name)
        confirm_local_rules_untouched()


# ---------------------------------------------------------------------------
# Gate 5 red-team proof -- the real search_files 20/4727 benign FP (dynamic)
# ---------------------------------------------------------------------------

def prove_gate5() -> None:
    """Reconstructs 100108's ORIGINAL draft (traversal match + the 100101
    suffix negate, but no tool_name scope) -- the exact version that
    produced a real, measured 20/4727 false positive from `search_files`'
    legitimate directory navigation during SAF-T1105's own build
    (docs/PHASE6-T1105-REPORT.md). Confirms gate5_benign_fp would have
    caught this before the rule was ever installed live."""
    confirm_local_rules_untouched()
    fixture_file = FIXTURES_DIR / "gate5_naive_100108_no_toolname_scope.xml"
    container_name = "zz_redteam_gate5.xml"

    redteam_detection = Detection(
        technique_id="SAF-T9996", name="redteam_naive_100108_no_toolname_scope",
        detection_type="structural", status="proposed",
        mitre_attack_ids=[], mitre_atlas_ids=[], description="red-team gate5 fixture",
        backends=[BackendEntry(
            backend="wazuh_rule",
            logic_ref=LogicRef(wazuh_rule_ids=["100196"], rule_file="framework/tests/redteam_fixtures/gate5"),
            consumes="raw_telemetry", parent_rule="100100",
        )],
        expected_signal={}, session_key=SessionKey(primary_field="session_id"),
        fixtures={}, known_gaps=[],
    )

    install_temp_rule(fixture_file, container_name)
    try:
        benign_lines = [l for l in (REPO_ROOT / "data" / "benign_corpus_v2.jsonl").read_text().splitlines() if l.strip()]
        matched = run_batch(benign_lines)
        benign_pairs = list(zip(benign_lines, matched))
        violations = gate5_benign_fp(redteam_detection, benign_pairs)
        caught = len(violations) > 0
        record("gate5_benign_fp", caught,
               f"reconstructed 100108's original draft (no tool_name scope) against the full "
               f"4727-record benign corpus -- found {len(violations)} violation(s) "
               f"(historical measurement: 20/4727, all from search_files) -- "
               + ("caught, would have blocked this draft before it was ever installed live"
                  if caught else "NOT CAUGHT"))
    finally:
        remove_temp_rule(container_name)
        confirm_local_rules_untouched()


def main() -> int:
    prove_gate1()
    prove_gate3()
    prove_gate2()
    prove_gate4()
    prove_gate5()

    print()
    n_pass = sum(1 for _, ok, _ in results if ok)
    print(f"{n_pass}/{len(results)} red-team fixtures caught by their gate")
    return 0 if n_pass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
