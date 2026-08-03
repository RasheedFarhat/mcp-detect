#!/usr/bin/env python3
"""Phase 5 -- adversarial evasion measurement (docs/PHASE5-DESIGN.md).
Generates docs/PHASE5-REPORT.md.

Deliberately reuses lab/analysis/report.py's primitives (rule-sync gate, batch
wazuh-logtest runner, join/normalization) rather than reimplementing them --
see docs/PHASE5-DESIGN.md Section 2. Also reuses lab/baseline/watch.py directly
for the rug-pull evasions (E10-E12), since "did this drift" is a two-stage
question here: does lab/baseline/watch.py emit a drift record at all, and if so,
does 100201 fire on it -- both via the real code, never asserted.

Usage:
  python3 lab/analysis/evasion_report.py     generate docs/PHASE5-REPORT.md
"""
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "lab" / "analysis"))
sys.path.insert(0, str(REPO_ROOT / "lab" / "baseline"))

import report as report_mod  # noqa: E402
import watch as watch_mod  # noqa: E402

EVASION_CORPUS_PATH = REPO_ROOT / "data" / "evasion_corpus_v1.jsonl"
REPORT_PATH = REPO_ROOT / "docs" / "PHASE5-REPORT.md"
GENERATOR_ID = "mcp-detect-analysis-evasion-report/1.0"

NO_ALERT_RULE_IDS = {report_mod.NO_ALERT_RULE_ID, "100200"}  # both parents are level-0, no-alert

# Evasion class metadata: which rule(s) it targets, what mechanism, and (per
# your item B) whether a successful evasion plausibly preserves attack
# efficacy or trades detection-evasion for degraded/nonfunctional attack
# behavior. Judged from the actual generated content, not assumed.
EXFIL_HOP_FAMILY = {"100103", "100104", "100105", "100106", "100107"}

# Historical narrative of what happened during this round's build -- hand-
# authored, not computed, same as every prior phase's "Build results"
# section (docs/PHASE3A-DESIGN.md, docs/PHASE3B-DESIGN.md). The tables
# below reflect the CURRENT, post-hardening rule -- this section is what
# makes E3a's "caught" verdict legible as "fixed mid-round," not "always
# passed," and records the E5 finding your sign-off asked to be flagged,
# not silently worked around.
HARDENING_HISTORY = """\
## What happened during this round, in order

1. **First measurement (pre-hardening)**: all 12 evasion classes run \
against the rule set as it stood at the start of Phase 5. Result: 11 of \
12 true evasion attempts succeeded, including **both** E3 sub-cases (E3a \
zero-width insertion, E3b homoglyph substitution) against `100102`.
2. **E3 investigated**: confirmed via `wazuh-logtest` that Wazuh's PCRE2 \
build supports `(*UTF)(*UCP)` mode and `\\p{Cf}` (Unicode category \
"Format" -- zero-width/invisible characters) *before* writing anything. \
Hardened `100102`'s keyword alternation to tolerate `\\p{Cf}*` between \
every letter of every keyword -- a genuine generalization (defeats any \
insertion of any Format-category character, not the one specimen E3a \
used), confirmed via `wazuh-logtest` to **not** also match E3b's \
homoglyph substitution (`\\p{Cf}` doesn't touch printable characters), \
and confirmed via full-corpus batch `wazuh-logtest` to introduce **zero** \
new benign false positives (4727/4727 still land on `100100` only) and \
**zero** regressions on any other rule's canonical recall count.

   **This fix's own honesty boundary, stated as plainly as the original \
attacks' -- do not read "E3a now caught" as "the class is closed":** the \
`\\p{Cf}` generalization was validated against exactly ONE Format-category \
character (U+200B, the zero-width space E3a happened to use) plus the \
full existing corpus. It was never tested against any of the dozens of \
other codepoints in the same Unicode category (zero-width joiner U+200D, \
zero-width non-joiner U+200C, word joiner U+2060, BOM U+FEFF, and more). \
The pattern's own construction (`\\p{Cf}*` -- the whole category, not one \
enumerated codepoint) gives good reason to *predict* those would also be \
caught, but that is a prediction from the regex's structure, not a \
measurement -- no session in this corpus exercises them. This is the \
exact same "self-authored variant" limit `docs/PHASE3A-DESIGN.md` and \
`docs/PHASE4-REPORT.md` already named for the original attacks, now \
applied to this round's own fix rather than to an attack.
3. **E3 installed live** (`docker compose stop`/`up`; see "Restart budget, \
clarified" below for what that tracking actually means). E3a now reflects \
"caught" in the tables below; E3b remains an accepted, documented gap \
(see the Tool Poisoning section) -- enumerating homoglyph-equivalence \
classes would be the same open-ended whack-a-mole as E1's keyword list, \
not a genuine fix.
4. **E5 investigated, per your explicit instruction to prove the gate \
before proposing anything**: the candidate fix (negate on \
`tool_arguments.path`'s *absence* instead of `tool_name`) was tested via \
`wazuh-logtest -v` against E5's own true positive (the spoofed call, \
which has no `path` key at all) *before* anything else. **Unambiguous \
result, stated precisely so "failed" isn't read as "inconclusive"**: the \
test itself ran cleanly to completion, no error -- the verbose trace \
shows `Trying rule: <candidate>` (the engine reached and evaluated the \
candidate rule) followed by a final matched rule of `100100` (the \
no-alert parent). That is a definitive negative result: with this fix \
installed, E5's actual malicious call would **not** alert. The fix does \
not work; the test that proved it worked correctly and completely. \
This confirms the exact negate-on-absent-field landmine \
`docs/PHASE3A-DESIGN.md` already found once for `100103`'s own first \
draft. No known construction in Wazuh's classic rule DSL expresses "fire \
unless a sensitive path argument is present" without hitting this same \
wall. **E5 stays document-only.** This is the finding your sign-off asked \
to be flagged rather than quietly worked around -- flagged here, not \
routed past.

**The recursion applies to this round's own hardening too, not just the \
original attacks**: E3's fix is validated against exactly the two E3 \
specimens this round authored (zero-width insertion, one homoglyph \
substitution) plus the full existing corpus -- it is not proven against \
every possible Format-category character or every possible invisible-\
character construction, only the ones exercised here (restated from the \
honesty note in step 2 above, because this is the kind of caveat that's \
easy to skim past once a table says "caught").

## Restart budget, clarified

"Restart budget N, M used" (this round: 2 proposed, 1 used) is a \
**self-imposed tracking convention inherited from Phase 3a, not an \
environment or technical cap.** It exists because repeated, rapid manager \
restarts caused real problems early in this project (a wedged manager \
requiring full container recreate, `docs/PHASE0.md` and \
`docs/WAZUH-NOTES.md` finding #5 -- container-lifecycle fragility under \
QEMU emulation, `linux/amd64` on an `arm64` host) -- the discipline is \
"iterate via `wazuh-logtest` exclusively, restart only for an \
already-validated candidate, and count/announce every restart," not "stop \
installing fixes after N restarts." **Confirmed explicitly: no validated \
fix was deferred this round to stay under any restart count.** Exactly \
one restart was needed (installing E3, the only fix that passed \
validation). E5 was never a candidate for live installation at all -- it \
was rejected by the negate-gate test in step 4 above, which has nothing \
to do with restart budget. Had E5 (or any other fix) passed validation, \
installing it would have been a normal, unremarkable use of a second \
restart, not something the "budget" would have blocked.
"""

EVASION_CLASSES = {
    "attack_evasion_e1_keyword_avoiding": {
        "target_rules": {"100102"}, "mechanism": "fixed keyword alternation",
        "efficacy": "preserves efficacy -- \"OBEY THIS PROTOCOL\" reads as a "
                    "clear imperative instruction to an LLM, no degradation",
    },
    "attack_evasion_e2_no_html_comment": {
        "target_rules": {"100102"}, "mechanism": "HTML-comment-only structural requirement",
        "efficacy": "preserves efficacy -- the bracketed instruction is at least "
                    "as readable/actionable to an LLM as the original HTML-comment "
                    "version; arguably more visible, not less",
    },
    "attack_evasion_e3a_zero_width": {
        "target_rules": {"100102"},
        "mechanism": "literal keyword byte-match (invisible-character insertion) "
                     "-- HARDENED this round, see \"What happened during this round\" below",
        "efficacy": "preserves efficacy -- zero-width characters do not affect "
                    "how the word renders or tokenizes for most LLM tokenizers/"
                    "readers; the instruction remains fully legible",
    },
    "attack_evasion_e3b_homoglyph": {
        "target_rules": {"100102"},
        "mechanism": "literal keyword byte-match (homoglyph substitution) "
                     "-- deliberately NOT hardened, see below",
        "efficacy": "preserves efficacy -- a single homoglyph swap is visually "
                    "indistinguishable and unlikely to disrupt LLM comprehension",
    },
    "attack_evasion_e4_distance_bound": {
        "target_rules": {"100102"}, "mechanism": "the .{0,120} proximity bound",
        "efficacy": "preserves efficacy -- padding is inert filler; the actual "
                    "instruction text is unchanged and fully readable",
    },
    "attack_evasion_e5_toolname_spoof": {
        "target_rules": set(EXFIL_HOP_FAMILY),
        "mechanism": "negate-list tool-name-based exclusion (exfil hop only -- "
                     "the read hop is an unmodified real read, not part of what "
                     "this class is testing)",
        "efficacy": "preserves efficacy -- the tool's real behavior (forwarding "
                    "data to a destination URL) is unaffected by what it's named; "
                    "the name is only ever seen by the rule and the calling model",
    },
    "attack_evasion_e6_untested_key": {
        "target_rules": set(EXFIL_HOP_FAMILY), "mechanism": "5-key-family enumeration boundary",
        "efficacy": "preserves efficacy -- the tool still receives and forwards "
                    "the secret; only the argument's key name changed",
    },
    "attack_evasion_e7_secret_shape": {
        "target_rules": set(EXFIL_HOP_FAMILY), "mechanism": "fixed secret-shape regex",
        "efficacy": "preserves efficacy -- the ghp_-shaped synthetic value is a "
                    "valid credential format; the Slack shape is deliberately redacted",
    },
    "attack_evasion_e8_encoded_payload": {
        "target_rules": set(EXFIL_HOP_FAMILY), "mechanism": "literal-string/prefix matching",
        "efficacy": "preserves efficacy for a real attacker -- base64 is "
                    "trivially reversible by the attacker's own receiving "
                    "infrastructure; confirmed the sink received the full, "
                    "decodable payload (see build log)",
    },
    "attack_evasion_e9_read_path": {
        "target_rules": {"100101"}, "mechanism": "anchored path-suffix regex",
        "efficacy": "preserves efficacy -- .env.bak carries byte-identical "
                    "content to .env; nothing about the secret is degraded",
    },
}


def load_evasion_corpus_lines() -> list[str]:
    return [l for l in EVASION_CORPUS_PATH.read_text().splitlines() if l.strip()]


def group_final_rules_by_task(lines: list[str], matched: list) -> dict:
    """task_id -> sorted list of alert-level rule ids that fired anywhere
    among its records (excludes both no-alert parents)."""
    joined = report_mod.normalize_and_join(lines, matched)
    by_task = defaultdict(set)
    for jr in joined:
        task = jr.raw.get("task_id")
        by_task.setdefault(task, set())
        if jr.matched_rule_id and jr.matched_rule_id not in NO_ALERT_RULE_IDS:
            by_task[task].add(jr.matched_rule_id)
    return {task: sorted(rules) for task, rules in by_task.items()}


def run_rugpull_watcher_on_evasion_corpus(lines: list[str]) -> list[dict]:
    """E10/E11/E12 use isolated server_command tags, so a fresh, empty
    baseline state (no dependency on the canonical rug_pull baseline) is
    correct and sufficient -- each establishes and tests its own baseline
    entirely within this corpus."""
    state = watch_mod.empty_state()
    events = []
    for line in lines:
        record = __import__("json").loads(line)
        events.extend(watch_mod.process_record(record, state))
    return events


def main() -> None:
    rule_sha = report_mod.verify_rule_sync()
    wazuh_version = report_mod.get_wazuh_version()
    canonical_inputs = report_mod.load_inputs()
    evasion_lines = load_evasion_corpus_lines()

    drift_events = run_rugpull_watcher_on_evasion_corpus(evasion_lines)
    drift_lines = [__import__("json").dumps(e) for e in drift_events]
    print(f"rug-pull watcher (evasion corpus, fresh state): {len(drift_events)} "
          f"drift record(s) emitted", file=sys.stderr)

    # One big batch: full regression (benign + canonical attack + canonical
    # drift) plus the evasion corpus and its own drift records, all through
    # the real engine in one pass.
    all_lines = (canonical_inputs["benign_lines"] + canonical_inputs["malicious_lines"]
                 + canonical_inputs["drift_lines"] + evasion_lines + drift_lines)
    all_matched = report_mod.run_wazuh_logtest_batch(all_lines)

    n_benign = len(canonical_inputs["benign_lines"])
    n_malicious = len(canonical_inputs["malicious_lines"])
    n_canon_drift = len(canonical_inputs["drift_lines"])
    n_evasion = len(evasion_lines)

    benign_matched = all_matched[:n_benign]
    malicious_matched = all_matched[n_benign:n_benign + n_malicious]
    canon_drift_matched = all_matched[n_benign + n_malicious:n_benign + n_malicious + n_canon_drift]
    evasion_matched = all_matched[n_benign + n_malicious + n_canon_drift:
                                  n_benign + n_malicious + n_canon_drift + n_evasion]
    evasion_drift_matched = all_matched[n_benign + n_malicious + n_canon_drift + n_evasion:]

    # Regression check: same numbers Phase 4 already established must be unchanged.
    benign_alerts = sum(1 for r in benign_matched if r not in NO_ALERT_RULE_IDS)
    regression_ok = (benign_alerts == 0)
    print(f"regression check: {benign_alerts}/{n_benign} benign records alerted "
          f"({'OK' if regression_ok else 'REGRESSION -- INVESTIGATE'})", file=sys.stderr)

    task_results = group_final_rules_by_task(evasion_lines, evasion_matched)
    drift_task_results = {}
    if drift_lines:
        drift_joined = report_mod.normalize_and_join(drift_lines, evasion_drift_matched)
        by_task = defaultdict(set)
        for jr in drift_joined:
            by_task[jr.raw.get("task_id")].add(jr.matched_rule_id)
        drift_task_results = {t: sorted(r) for t, r in by_task.items()}

    render_report(
        rule_sha=rule_sha, wazuh_version=wazuh_version,
        n_benign=n_benign, benign_alerts=benign_alerts,
        n_evasion=n_evasion, task_results=task_results,
        drift_task_results=drift_task_results, drift_events=drift_events,
    )


def fmt_verdict(evaded: bool) -> str:
    return "**EVADED**" if evaded else "caught"


TP_TASK_IDS = ["attack_evasion_e1_keyword_avoiding", "attack_evasion_e2_no_html_comment",
               "attack_evasion_e3a_zero_width", "attack_evasion_e3b_homoglyph",
               "attack_evasion_e4_distance_bound"]
CE_TASK_IDS = ["attack_evasion_e5_toolname_spoof", "attack_evasion_e6_untested_key",
               "attack_evasion_e7_secret_shape", "attack_evasion_e8_encoded_payload",
               "attack_evasion_e9_read_path"]


def targeted_and_other_fired(tid: str, task_results: dict) -> tuple[set, set]:
    """Split what actually fired on this task_id into (rules the class was
    testing) vs (anything else) -- e.g. E5/E6/E8 each also have an
    unmodified real .env read in the same task_id, which always trips
    100101 regardless of whether the class's own targeted evasion (on the
    exfil hop) succeeded. Conflating the two would misreport a successful
    evasion as 'caught' by a signal that was never in scope for that class."""
    fired = set(task_results.get(tid, []))
    target = EVASION_CLASSES[tid]["target_rules"]
    return fired & target, fired - target


def render_report(*, rule_sha, wazuh_version, n_benign, benign_alerts,
                   n_evasion, task_results, drift_task_results, drift_events) -> None:
    tp_evaded = [t for t in TP_TASK_IDS if not targeted_and_other_fired(t, task_results)[0]]
    ce_evaded = [t for t in CE_TASK_IDS if not targeted_and_other_fired(t, task_results)[0]]
    e11_evaded = not drift_task_results.get("attack_evasion_e11_behavior_only")
    e12_evaded = not drift_task_results.get("attack_evasion_e12_pulled")
    e10_fired = bool(drift_task_results.get("attack_evasion_e10_legit_upgrade"))

    # 11 true evasion attempts (E1-E9, E11, E12) -- E10 is an FP probe, not
    # an evasion attempt, reported separately and not counted here.
    n_true_evasions = len(TP_TASK_IDS) + len(CE_TASK_IDS) + 2
    n_evaded_total = len(tp_evaded) + len(ce_evaded) + (1 if e11_evaded else 0) + (1 if e12_evaded else 0)
    evaded_names = tp_evaded + ce_evaded
    if e11_evaded:
        evaded_names.append("attack_evasion_e11_behavior_only")
    if e12_evaded:
        evaded_names.append("attack_evasion_e12_pulled")

    out = []
    out.append("<!-- GENERATED FILE -- produced by lab/analysis/evasion_report.py. "
                "Do not hand-edit; re-run `python3 lab/analysis/evasion_report.py` to update. -->")
    out.append("# Phase 5 Report — Adversarial Evasion Testing\n")

    out.append("## Provenance\n")
    out.append(f"- Generator: `{GENERATOR_ID}`")
    out.append(f"- `wazuh/local_rules.xml` sha256 (verified byte-identical to the live "
                f"manager's loaded rule file): `{rule_sha}`")
    out.append(f"- Wazuh version: `{wazuh_version}`")
    out.append(f"- Inputs: full Phase 4 regression set ({n_benign} benign records) plus "
                f"`data/evasion_corpus_v1.jsonl` ({n_evasion} records, 17 task_ids across "
                f"12 evasion classes)")
    out.append(f"- Regression: **{benign_alerts}/{n_benign}** benign records alerted "
                f"({'no regression' if benign_alerts == 0 else 'REGRESSION -- investigate before trusting anything below'})")
    out.append("- No wall-clock timestamp embedded, same reasoning as `docs/PHASE4-REPORT.md`.")

    out.append("\n## Executive summary\n")
    out.append(f"**This report's success condition is finding gaps, not avoiding them.** "
                f"**{n_evaded_total} of {n_true_evasions} true evasion attempts succeed against "
                f"the rule set as it currently stands** (E1-E9, E11, E12 — E10 is a "
                f"false-positive probe, not an evasion attempt, reported separately below): "
                f"{', '.join(evaded_names)}. One of these (E3a) was originally a successful "
                f"evasion too, closed by a hardening fix applied during this same round -- see "
                f"\"What happened during this round\" below for the full sequence, including a "
                f"proposed fix for a different class (E5) that was tested and rejected, not "
                f"silently dropped. **\"E3a now caught\" is not \"the class is closed\"** -- the "
                f"fix was validated against exactly one Format-category character plus the "
                f"existing corpus, and every other codepoint in that category is a prediction "
                f"from the pattern's structure, not a measurement (full caveat below). These are "
                f"real gaps in the current ruleset, stated plainly, not softened into another "
                f"set of caveated 100% tables.\n")

    out.append(HARDENING_HISTORY)

    out.append("## Tool poisoning (`100102`)\n")
    out.append("| class | mechanism targeted | targeted rule fired? | verdict |")
    out.append("|---|---|---|---|")
    for tid in TP_TASK_IDS:
        targeted, other = targeted_and_other_fired(tid, task_results)
        meta = EVASION_CLASSES[tid]
        out.append(f"| `{tid}` | {meta['mechanism']} | "
                    f"{','.join(sorted(targeted)) if targeted else '(none)'} | "
                    f"{fmt_verdict(not targeted)} |")
    out.append("\n**Attack-efficacy note for each evasion that succeeded** (per your item B "
                "— evading detection is a weaker finding if the payload also stops working):")
    for tid in tp_evaded:
        out.append(f"- `{tid}`: {EVASION_CLASSES[tid]['efficacy']}")

    out.append("\n## Credential exfiltration (`100101` / `100103`–`107`)\n")
    out.append("Each class's own \"targeted rule fired?\" column checks *only* the rule(s) "
                "that specific class is testing — several of these sessions (E5/E6/E8) also "
                "include an unmodified real `.env` read alongside the actual evasion attempt "
                "on the exfil hop, and that unmodified read always trips `100101` regardless "
                "of whether the class's own target evaded or not. Shown separately so an "
                "unrelated signal firing isn't misread as the targeted evasion having failed.\n")
    out.append("| class | mechanism targeted | targeted rule fired? | other signal fired? | verdict |")
    out.append("|---|---|---|---|---|")
    for tid in CE_TASK_IDS:
        targeted, other = targeted_and_other_fired(tid, task_results)
        meta = EVASION_CLASSES[tid]
        out.append(f"| `{tid}` | {meta['mechanism']} | "
                    f"{','.join(sorted(targeted)) if targeted else '(none)'} | "
                    f"{','.join(sorted(other)) if other else '(none)'} | "
                    f"{fmt_verdict(not targeted)} |")
    out.append("\n**Attack-efficacy note for each evasion that succeeded:**")
    for tid in ce_evaded:
        out.append(f"- `{tid}`: {EVASION_CLASSES[tid]['efficacy']}")
    e9_other = targeted_and_other_fired("attack_evasion_e9_read_path", task_results)[1]
    if e9_other:
        out.append(f"\n**E9 evades its own targeted rule (`100101`) but is not a full "
                    f"bypass of the attack overall** — the *content* signal "
                    f"(`{','.join(sorted(e9_other))}`) still fires on the exfil step, since "
                    f"the exfiltrated content is byte-identical to the real `.env`. "
                    f"Defense-in-depth catching what the path-based signal alone would have "
                    f"missed — worth stating precisely rather than either calling this a "
                    f"clean evasion or ignoring the partial result.")

    out.append("\n## Rug pull (`100201` / `lab/baseline/watch.py`)\n")
    out.append("Two-stage measurement: does `lab/baseline/watch.py` emit a drift record at all "
                "(the detector's own decision), and if so, does `100201` fire on it (Wazuh's "
                "side). Both checked via the real code, not asserted.\n")
    out.append("| class | lab/baseline/watch.py emitted drift? | 100201 fired? |")
    out.append("|---|---|---|")
    for suffix, tid in [("e10_legit_upgrade", "attack_evasion_e10_legit_upgrade"),
                        ("e11_behavior_only", "attack_evasion_e11_behavior_only"),
                        ("e12_pulled", "attack_evasion_e12_pulled")]:
        drifted = tid in drift_task_results
        fired_rules = drift_task_results.get(tid, [])
        out.append(f"| `{suffix}` | {'yes' if drifted else '**no**'} | "
                    f"{','.join(fired_rules) if fired_rules else ('n/a -- nothing to fire on' if not drifted else '**no**')} |")

    out.append(f"\n**E10 (legitimate version bump) — stated at its real operational "
                f"severity, not as a footnote**: {'confirmed to fire' if e10_fired else 'did NOT fire (unexpected -- investigate)'}. "
                f"**As built, this detector fires on every legitimate update to a monitored "
                f"tool or server, indistinguishably from a real rug pull.** Without the "
                f"allowlist/re-baseline workflow `docs/PHASE3B-DESIGN.md` explicitly declined "
                f"to build, this makes the detector *operationally close to unusable* in any "
                f"environment where the monitored MCP servers are ever legitimately upgraded — "
                f"every routine version bump is a false alarm indistinguishable from an actual "
                f"attack. This is a real limitation of the current design, not a tuning gap.")

    out.append(f"\n**E11 (behavior-only rug pull)**: {'confirmed zero drift, as predicted' if e11_evaded else 'unexpectedly drifted (investigate)'}. "
                f"This is a structural, **not fixable within this architecture** blind spot: "
                f"there is no field in MCP's protocol surface this project captures that "
                f"exposes runtime behavior for hashing. A rug pull that changes only what a "
                f"tool *does*, never what it *advertises*, is invisible to this whole "
                f"detection philosophy, full stop — document, not a gap to chase.")

    out.append(f"\n**E12 (session-conditional serving)**: {'EVADED (unexpected -- investigate)' if e12_evaded else 'confirmed caught, as predicted -- TOFU-then-alert survives multiple prior clean observations'}, "
                f"as predicted in `docs/PHASE5-DESIGN.md`. Not a gap.")

    expected_drift_tasks = {"attack_evasion_e10_legit_upgrade", "attack_evasion_e12_pulled"}
    unexpected_drift = {t: rules for t, rules in drift_task_results.items() if t not in expected_drift_tasks}
    if unexpected_drift:
        out.append("\n### Unintended cross-scenario drift, found in this corpus too (not hidden)\n")
        out.append("`lab/baseline/watch.py` doesn't know or care what an evasion class is testing — "
                    "it only sees `(tool_name, server_command)` pairs and their hashes. This "
                    "corpus reuses `poisoned_tool_server.py` (same tool name, same server "
                    "command) across E1/E2/E3a/E3b/E4, each with a genuinely different "
                    "description, and reuses `exfil_sink_server.py`'s `exfiltrate` tool across "
                    "E6/E7/E8/E9 with a schema that changes between E6 (`msg` key) and the "
                    "rest (`data` key). Exactly the same class of finding "
                    "`docs/PHASE4-REPORT.md` already documented for 3a's own variant "
                    "harness — the rug-pull detector is behaving exactly as designed (real "
                    "schema drift, correctly detected); it's this corpus's own construction "
                    "that reuses one server identity across variants with different content, "
                    "not a new mechanism.\n")
        out.append("| task_id | rule(s) fired on the drift record |")
        out.append("|---|---|")
        for t in sorted(unexpected_drift):
            out.append(f"| `{t}` | {','.join(unexpected_drift[t]) if unexpected_drift[t] else '(none)'} |")
        out.append("\n**This does not change any evasion verdict above** — with one now-stale "
                    "name needing a correction rather than a silent edit: E2/E3b/E4 still evade "
                    "`100102` (the rule they actually target); E7 still evades `100103`–`107` "
                    "(the rule it targets). **E3a is the one exception, and for an unrelated "
                    "reason**: it now shows `100102` in the *targeted*-rule table above because "
                    "of the E3 hardening applied this round, not because of anything in this "
                    "cross-scenario table — its appearance here (the rug-pull rule firing on an "
                    "unrelated tool_poisoning task_id) was already true before the hardening and "
                    "remains an unrelated artifact of this corpus's construction, exactly like "
                    "the other four rows. An unrelated rule firing on the same task_id via an "
                    "unrelated mechanism is not a catch of the evasion being tested — stated "
                    "explicitly so this table isn't misread as \"actually, some of these got "
                    "caught after all.\"")
        out.append("\n**This isn't just an observation that happens to hold — it's structurally "
                    "guaranteed by how this data is computed, confirmed by reading the actual "
                    "code path, not just checking today's output.** Every verdict above comes "
                    "from `targeted_and_other_fired()`, which reads *only* `task_results` — a "
                    "dict built exclusively from the raw `data/evasion_corpus_v1.jsonl` "
                    "records' own rule matches. Those raw records never carry the "
                    "`mcp_drift_marker` field `100200` requires, so they **cannot** match "
                    "`100200`/`100201` at all, structurally, regardless of what "
                    "`lab/baseline/watch.py` does downstream. The 5 firings in the table above live "
                    "entirely in a separate dict, `drift_task_results` — built from the derived "
                    "drift records on a completely different code path — which "
                    "`targeted_and_other_fired()` never reads. There is no path by which a "
                    "`100201` firing could reach a TP/CE verdict; this was true before this "
                    "table existed, not a filter applied after the fact.")

    out.append("\n## The recursion, restated for this specific round")
    out.append("\nAny future hardening validated only against this round's own evasion "
                "corpus inherits the exact self-authored-variant problem `docs/PHASE3A-DESIGN.md` "
                "and `docs/PHASE4-REPORT.md` already named for the original attacks. A clean "
                "result against `data/evasion_corpus_v1.jsonl` is evidence a fix beats the "
                "specific evasions *this round* thought to author — not evidence of "
                "adversarial robustness in general. A differently-minded adversary, or a "
                "future Phase 6 red-team round, could plausibly find a class this round "
                "didn't consider.")

    out.append("\n## Deferred infrastructure, named on the record")
    out.append("\nThe only genuine generalization available for E6 (the 6th-argument-key "
                "gap) is moving that content-signal check outside Wazuh entirely — an "
                "external, `tool_arguments`-shape-agnostic scanner that checks *any* leaf "
                "value under `tool_arguments` for secret-shaped content, regardless of key "
                "name, architecturally similar to how `lab/baseline/watch.py` already moved "
                "rug-pull detection outside Wazuh for the same class of reason (no primitive "
                "inside Wazuh's rule DSL expresses it). Not built this round, per your "
                "sign-off — named here as the real fix, so the deferral is a decision on "
                "record, not a gap that gets silently rediscovered next time.")
    out.append("\n**The same external scanner would also close E5**, discovered while proving "
                "the negate gate above: E5's tool-name-spoofing gap and E6's key-name gap are "
                "symptoms of the same underlying limitation (Wazuh's classic rule DSL can't "
                "express \"any tool call, any argument key, regardless of tool name\" as one "
                "condition). A Python scanner checking \"does `tool_arguments` have a `path` "
                "key matching the sensitive suffix\" is a native, trivial absence check with no "
                "negate-on-absent-field landmine at all — the exact wall that ruled out fixing "
                "E5 inside Wazuh's rule DSL. One piece of deferred infrastructure, not two, "
                "closes both gaps.")

    REPORT_PATH.write_text("\n".join(out) + "\n")
    print(f"wrote {REPORT_PATH.relative_to(REPO_ROOT)}", file=sys.stderr)


if __name__ == "__main__":
    main()
