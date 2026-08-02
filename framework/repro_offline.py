#!/usr/bin/env python3
"""Offline reproduction of docs/PHASE4-REPORT.md's per-technique recall and
aggregate false-positive numbers, from committed frozen files -- no Docker,
no Ollama, no live Wazuh manager needed for the default (`--tier sample`)
path. See docs/REPRO-VERIFICATION.md for the verified, from-a-clean-clone
proof this actually works, and exactly what it proves versus what it
doesn't.

Two public tiers:
  --tier sample (default) -- Reproduces sample-level numbers from
    data/attack_corpus_sample_v1.jsonl + data/benign_corpus_v2.jsonl, both
    committed to this repo, plus their committed `.golden_matches.json`
    files. This is the public proof of method -- runs from a clean clone,
    zero infrastructure.
  --tier full -- Reproduces docs/PHASE4-REPORT.md's exact published numbers
    (12/12, 11/11, 11/11, 3/3 recall; 0/4,727 FP), pointed at data/full/ --
    the complete self-authored attack corpus committed in this repository.
    Compares against
    docs/PHASE4-REPORT.md's own published text via
    framework/parity_check.py's own parser, not a second hand-maintained
    "expected numbers" file.

Mechanism, stated plainly: a `.golden_matches.json` file is the real,
already-measured final-matched-rule-id-per-line output of a genuine
`wazuh-logtest` batch run, captured once (see --capture-golden, which DOES
need the live stack) and committed/frozen alongside its corpus. Replaying
it is reusing real prior measurement, not reimplementing rule matching in
Python -- the one thing this project has never done and isn't starting
here. This script reuses framework/coverage.py's own
`build_coverage_table()` unmodified, feeding it a `run` dict built from
frozen files instead of `run_full_pipeline()`'s live fetches -- no
aggregation logic is duplicated or reimplemented.

This proves REPRODUCIBILITY of the reported numbers from committed
artifacts, not that the CURRENT rules still behave this way against a live
engine right now -- that remains framework/parity_check.py's job
(live-only, unchanged by this addition).

Offline replay is pinned to a specific wazuh/local_rules.xml sha256, and
self-invalidates when the rules drift: every `.golden_matches.json` stamps
the rule_sha256 it was captured against (same discipline
analysis/report.py's own verify_rule_sync() already uses), and
build_run() refuses to replay -- loud RuntimeError, not a silently stale
pass -- if that sha no longer matches the currently committed rule file.
See framework/tests/test_repro_offline_stale_rules.py.

Usage:
  python3 framework/repro_offline.py                       # public tier, offline, exit 0/1
  python3 framework/repro_offline.py --tier full           # complete public corpus, offline
  python3 framework/repro_offline.py --capture-golden --tier sample   # (re)capture -- needs live stack
  python3 framework/repro_offline.py --capture-golden --tier full     # (re)capture -- needs live stack
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "analysis"))

import report as report_mod  # noqa: E402

RULES_PATH = REPO_ROOT / "wazuh" / "local_rules.xml"
BENIGN_PATH = REPO_ROOT / "data" / "benign_corpus_v2.jsonl"
BENIGN_GOLDEN_PATH = REPO_ROOT / "data" / "benign_corpus_v2.golden_matches.json"

TIER_PATHS = {
    "sample": {
        "attack_corpus": REPO_ROOT / "data" / "attack_corpus_sample_v1.jsonl",
        "rugpull_alerts": REPO_ROOT / "data" / "rugpull_alerts_sample_v1.jsonl",
        "golden": REPO_ROOT / "data" / "attack_corpus_sample_v1.golden_matches.json",
        "expected": REPO_ROOT / "data" / "attack_corpus_sample_v1.expected_numbers.json",
    },
    "full": {
        "attack_corpus": REPO_ROOT / "data" / "full" / "attack_corpus_full_v1.jsonl",
        "rugpull_alerts": REPO_ROOT / "data" / "full" / "rugpull_alerts_full_v1.jsonl",
        "golden": REPO_ROOT / "data" / "full" / "attack_corpus_full_v1.golden_matches.json",
        "expected": None,  # compared against docs/PHASE4-REPORT.md's own text instead
    },
}


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Both corpus tiers should be committed in this "
            f"repository."
        )
    return [l for l in path.read_text().splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# Golden capture (LIVE -- needs Docker/Ollama/Wazuh; run once, commit the result)
# ---------------------------------------------------------------------------

def capture_golden_for_tier(tier: str) -> None:
    from framework.structural import run_batch, verify_rule_sync, get_wazuh_version

    cfg = TIER_PATHS[tier]
    rule_sha = verify_rule_sync()
    wazuh_version = get_wazuh_version()

    attack_lines = load_lines(cfg["attack_corpus"])
    drift_lines = load_lines(cfg["rugpull_alerts"])
    matches = run_batch(attack_lines + drift_lines)

    cfg["golden"].write_text(json.dumps({
        "wazuh_version": wazuh_version,
        "rule_sha256": rule_sha,
        "attack_corpus_record_count": len(attack_lines),
        "rugpull_alerts_record_count": len(drift_lines),
        "matches": matches,
    }, indent=2) + "\n")
    print(f"captured {len(matches)} golden matches ({len(attack_lines)} attack + "
          f"{len(drift_lines)} drift) -> {cfg['golden'].relative_to(REPO_ROOT)}", file=sys.stderr)


def capture_golden_for_benign() -> None:
    from framework.structural import run_batch, verify_rule_sync, get_wazuh_version

    rule_sha = verify_rule_sync()
    wazuh_version = get_wazuh_version()
    benign_lines = load_lines(BENIGN_PATH)
    matches = run_batch(benign_lines)

    BENIGN_GOLDEN_PATH.write_text(json.dumps({
        "wazuh_version": wazuh_version,
        "rule_sha256": rule_sha,
        "record_count": len(benign_lines),
        "matches": matches,
    }, indent=2) + "\n")
    print(f"captured {len(matches)} golden matches -> "
          f"{BENIGN_GOLDEN_PATH.relative_to(REPO_ROOT)}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Offline replay
# ---------------------------------------------------------------------------

def current_rules_sha256(rules_path: Path | None = None) -> str:
    """sha256 of the rule file a golden capture should be checked against --
    parameterized (not hardcoded to RULES_PATH) purely so a test can point
    this at a temp mutated copy without touching the real committed rule
    file. Defaults to the real, committed wazuh/local_rules.xml."""
    path = rules_path if rules_path is not None else RULES_PATH
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_golden_rule_sha(golden: dict, golden_path: Path, current_sha: str) -> None:
    """Refuses to replay a golden capture whose own recorded rule_sha256
    doesn't match the rules being checked against right now. A golden file
    is a snapshot of what wazuh-logtest said about a specific, named rule
    set (--capture-golden always stamps the sha it ran against, mirroring
    analysis/report.py's own verify_rule_sync() discipline) -- if the rules
    have since changed, replaying it would report numbers for a rule set
    that no longer exists, silently. Loud failure, not a stale pass."""
    golden_sha = golden.get("rule_sha256")
    if golden_sha != current_sha:
        raise RuntimeError(
            f"REFUSING TO REPLAY STALE GOLDEN RESULTS.\n"
            f"  {golden_path.name}'s own rule_sha256 ({golden_sha!r}) does not match "
            f"the rules being checked against right now ({current_sha!r}).\n"
            f"  The rules have changed since these golden wazuh-logtest verdicts were "
            f"captured -- replaying them now would report numbers for a rule set that "
            f"no longer exists.\n"
            f"  Re-run `--capture-golden` (needs the live stack: Docker + Wazuh) to "
            f"refresh {golden_path.name} against the current rules before trusting "
            f"any offline replay."
        )


def build_run(tier: str, *, rules_path: Path | None = None) -> dict:
    """Constructs exactly the `run` dict shape framework/coverage.py's
    build_coverage_table() expects, sourced from frozen files + committed
    golden matches instead of run_full_pipeline()'s live fetches. No
    aggregation logic lives here -- build_coverage_table() is reused
    unmodified.

    `rules_path` is test-only (see framework/tests/test_repro_offline_stale_rules.py)
    -- production callers always use the real committed rule file."""
    from framework.registry import load_registry

    cfg = TIER_PATHS[tier]
    detections = load_registry()
    current_sha = current_rules_sha256(rules_path)

    benign_lines = load_lines(BENIGN_PATH)
    if not BENIGN_GOLDEN_PATH.exists():
        raise FileNotFoundError(
            f"{BENIGN_GOLDEN_PATH} not found -- run --capture-golden once (needs the "
            f"live stack) before offline replay can work."
        )
    benign_golden = json.loads(BENIGN_GOLDEN_PATH.read_text())
    _verify_golden_rule_sha(benign_golden, BENIGN_GOLDEN_PATH, current_sha)
    benign_matches = benign_golden["matches"]
    if len(benign_matches) != len(benign_lines):
        raise RuntimeError(
            f"{BENIGN_GOLDEN_PATH.name} has {len(benign_matches)} entries for "
            f"{len(benign_lines)} benign records -- these must be captured together "
            f"and stay in lockstep; refusing to silently misattribute results"
        )

    attack_lines = load_lines(cfg["attack_corpus"])
    drift_lines = load_lines(cfg["rugpull_alerts"])
    if not cfg["golden"].exists():
        raise FileNotFoundError(
            f"{cfg['golden']} not found -- run --capture-golden --tier {tier} once "
            f"(needs the live stack) before offline replay can work."
        )
    golden = json.loads(cfg["golden"].read_text())
    _verify_golden_rule_sha(golden, cfg["golden"], current_sha)
    all_matches = golden["matches"]
    n_attack, n_drift = len(attack_lines), len(drift_lines)
    if len(all_matches) != n_attack + n_drift:
        raise RuntimeError(
            f"{cfg['golden'].name} has {len(all_matches)} entries but "
            f"{cfg['attack_corpus'].name}+{cfg['rugpull_alerts'].name} have "
            f"{n_attack}+{n_drift} lines -- these must be captured together and stay "
            f"in lockstep; refusing to silently misattribute results"
        )
    attack_matches = all_matches[:n_attack]
    drift_matches = all_matches[n_attack:]

    benign_joined = report_mod.normalize_and_join(benign_lines, benign_matches)
    attack_joined = report_mod.normalize_and_join(attack_lines + drift_lines, attack_matches + drift_matches)

    return {
        "detections": detections,
        "canonical": {"benign_lines": benign_lines},
        "benign_joined": benign_joined,
        "attack_joined": attack_joined,
    }


def render_and_check(tier: str, run: dict) -> tuple[str, bool]:
    from framework.coverage import build_coverage_table

    table = build_coverage_table(run)
    agg = table["aggregate_fp"]

    lines = [f"# Offline reproduction -- tier: {tier}\n"]
    lines.append(f"Aggregate benign FP: **{agg['alerting_records']}/{agg['total_records']}**\n")
    lines.append("| technique | scenario | recall label | hit/total |")
    lines.append("|---|---|---|---|")
    actual = {"aggregate_fp": (agg["alerting_records"], agg["total_records"]), "recall": {}}
    for name, d in table["detections"].items():
        for label, r in d["recall"].items():
            lines.append(f"| {d['technique_id']} | {d['scenario']} | {label} | {r['hit']}/{r['total']} |")
            actual["recall"][label] = (r["hit"], r["total"])

    ok, check_lines = compare_against_expected(tier, actual)
    lines.append("")
    lines.extend(check_lines)
    return "\n".join(lines) + "\n", ok


def compare_against_expected(tier: str, actual: dict) -> tuple[bool, list[str]]:
    out = []
    if tier == "full":
        # Compare against docs/PHASE4-REPORT.md's own published text, via
        # parity_check.py's own parser -- no second hand-maintained
        # "expected numbers" file for the tier that's supposed to match a
        # real published report exactly.
        sys.path.insert(0, str(REPO_ROOT / "framework"))
        import parity_check as parity_mod

        expected = parity_mod.parse_phase4_report(parity_mod.PHASE4_REPORT.read_text())
        checks = [
            ("tool_poisoning_html_comment", "tool_poisoning_recall"),
            ("read_hop", "read_hop_recall"),
            ("exfil_hop", "exfil_hop_recall"),
            ("rug_pull_baseline_drift", "rug_pull_recall"),
        ]
        all_ok = True
        for label, exp_key in checks:
            exp = expected[exp_key]
            got = actual["recall"].get(label)
            ok = got == tuple(exp) if isinstance(exp, tuple) else got == exp
            all_ok = all_ok and ok
            out.append(f"- `{label}` recall: expected {exp}, got {got} -- "
                        f"{'MATCH' if ok else 'MISMATCH'}")
        exp_fp = expected["aggregate_fp"]
        fp_ok = actual["aggregate_fp"] == tuple(exp_fp)
        all_ok = all_ok and fp_ok
        out.append(f"- aggregate FP: expected {exp_fp}, got {actual['aggregate_fp']} -- "
                    f"{'MATCH' if fp_ok else 'MISMATCH'}")
        out.append("")
        out.append(f"**{'PASSED' if all_ok else 'FAILED'} -- reproduces docs/PHASE4-REPORT.md's "
                    f"exact published numbers from the complete public corpus.**")
        return all_ok, out

    # sample tier -- compared against this repo's own committed expected_numbers.json
    exp_path = TIER_PATHS["sample"]["expected"]
    if not exp_path.exists():
        out.append(f"No {exp_path.name} committed yet -- nothing to compare against "
                    f"(first run should write one via --write-expected).")
        return False, out
    expected = json.loads(exp_path.read_text())
    all_ok = True
    for label, exp in expected["recall"].items():
        got = actual["recall"].get(label)
        ok = got == tuple(exp)
        all_ok = all_ok and ok
        out.append(f"- `{label}` sample recall: expected {exp}, got {got} -- "
                    f"{'MATCH' if ok else 'MISMATCH'}")
    fp_ok = actual["aggregate_fp"] == tuple(expected["aggregate_fp"])
    all_ok = all_ok and fp_ok
    out.append(f"- aggregate FP: expected {expected['aggregate_fp']}, got "
                f"{actual['aggregate_fp']} -- {'MATCH' if fp_ok else 'MISMATCH'}")
    out.append("")
    out.append(f"**{'PASSED' if all_ok else 'FAILED'} -- reproduces the committed "
                f"sample-level numbers (data/attack_corpus_sample_v1.summary.md) from "
                f"public files alone, no Docker/Ollama/Wazuh needed.**")
    return all_ok, out


def write_expected(tier: str, run: dict) -> None:
    """One-time authoring step for the sample tier's own expected_numbers.json
    -- records whatever build_coverage_table() actually computes, becoming
    the regression reference for every future offline replay. Not used for
    'full' (that tier is checked against docs/PHASE4-REPORT.md's real
    published text directly, never a hand-authored file)."""
    from framework.coverage import build_coverage_table

    if tier != "sample":
        raise ValueError("write_expected is only meaningful for the sample tier")
    table = build_coverage_table(run)
    agg = table["aggregate_fp"]
    recall = {}
    for name, d in table["detections"].items():
        for label, r in d["recall"].items():
            recall[label] = [r["hit"], r["total"]]
    TIER_PATHS["sample"]["expected"].write_text(json.dumps({
        "aggregate_fp": [agg["alerting_records"], agg["total_records"]],
        "recall": recall,
    }, indent=2) + "\n")
    print(f"wrote {TIER_PATHS['sample']['expected'].relative_to(REPO_ROOT)}", file=sys.stderr)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tier", choices=["sample", "full"], default="sample")
    parser.add_argument("--capture-golden", action="store_true",
                         help="(re)capture golden wazuh-logtest output -- needs the live stack")
    parser.add_argument("--write-expected", action="store_true",
                         help="(sample tier only) record current computed numbers as the "
                              "committed expected_numbers.json -- a one-time authoring step, "
                              "not something a verifier should ever need to pass")
    args = parser.parse_args()

    if args.capture_golden:
        capture_golden_for_benign()
        capture_golden_for_tier(args.tier)
        return 0

    run = build_run(args.tier)

    if args.write_expected:
        write_expected(args.tier, run)
        return 0

    report, ok = render_and_check(args.tier, run)
    print(report)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
