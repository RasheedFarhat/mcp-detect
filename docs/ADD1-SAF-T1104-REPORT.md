# ADD-1 / SAF-T1104 — Sensitive absolute-path read (build report)

The first detection authored in the post-productization-assessment maturity
work, closing a **previously-disclosed** gap rather than opening a new phase:
`docs/DISSECTION-FINDINGS.md` finding **D3** ("No detection for absolute-path
reads of sensitive files") and, equivalently, SAF-T1105's own registered
`known_gap` **E6** ("Absolute-path access without any `../` evades … this rule
matches the traversal MECHANISM, not arbitrary sensitive-path access").
Authored end to end through the framework — harness → rule → five gates →
frozen corpora → offline replay — exactly the path the roadmap requires for
any new detection.

## What was missing (the D3 gap, re-stated)

`100101` matches three named *suffixes* (`.env`/`id_rsa`/`.aws/credentials`);
`100108` matches the `../` *mechanism*. A clean **absolute** path to a
sensitive system file matches neither. Live-proven in the dissection: reading
`/etc/passwd` or `~/.ssh/authorized_keys` produced final match `100100` (the
parent anchor — **no alert**). The most obvious sensitive-read attack was
uncovered by construction.

## Grounding (SAF-MCP, via `gh api`, not memory)

Mapped to **SAF-T1104 — Over-Privileged Tool Abuse** (tactic Execution,
ATK-TA0002). Upstream's own README example is *"Using a file-reading tool to
access configuration files … beyond the tool's intended scope"* — a precise
description of this detection. (The placeholder id `SAF-T1006` considered
during scoping was rejected: `gh api` confirmed it is "User-Social-Engineering
Install", unrelated.) ATT&CK **T1068** (Exploitation for Privilege Escalation)
is cited from SAF-T1104's own MITRE ATT&CK Mapping list (`T1059`/`T1068`);
`T1068` over `T1059` because no shell command executes — only a file tool's
path argument. The data-access objective also aligns with `T1005` (Data from
Local System, the mapping SAF-T1105 uses), disclosed the same way SAF-T1105
disclosed its own ATT&CK-fit reasoning. OWASP: **MCP02** (privilege escalation
/ scope creep) — which this moves from NONE to PARTIAL in `--owasp-map` — and
**MCP10** (context over-sharing).

## The rule (`wazuh/local_rules.xml`, id `100109`)

```
method == tools/call
tool_name  ==  ^(read_file|read_text_file)$            (positive: content-exposing read tools)
tool_arguments.path  NEGATE (?i)(\.env$|id_rsa$|\.aws/credentials$)   (defer 100101's suffixes)
tool_arguments.path  NEGATE \.\.(/|\\)                 (defer 100108's traversal)
tool_arguments.path  (?i)(^/etc/(passwd|shadow|gshadow|sudoers)$|^/etc/ssh/|^/root/
                          |/\.ssh/(authorized_keys|known_hosts|config)$
                          |/proc/[0-9]+/environ$|^/proc/self/environ$|^/var/run/secrets/)
```

Both `negate`s are on a field (`tool_arguments.path`) that is **always present**
for this rule's own true positive — so this is not the negate-on-absent-field
landmine (`docs/PHASE3A-DESIGN.md`), same safe class as `100108`. The positive
signal is a **bounded, named list** of sensitive absolute targets — the same
disclosed-scope-boundary discipline as SAF-T1502's six credential shapes, not
an open-ended list.

## Attack corpus (real telemetry, not hand-crafted)

`lab/attacks/abs_path_read_harness.py` drives the real pinned MCP filesystem server
through the real lab/proxy/client stack (8 variants, one session each). The server
enforces its `/app/sandbox` root and denies every read — irrelevant to the
detection, which matches the **attempt** (the path argument), exactly as
SAF-T1105's harness already argued. 6 variants are the real signal
(`/etc/passwd`, `/etc/shadow`, `/proc/self/environ`,
`/home/agent/.ssh/authorized_keys`, `/etc/ssh/sshd_config`,
`/var/run/secrets/…/token`); 2 deliberately overlap `100101`'s suffixes
(`/root/.ssh/id_rsa`, `/home/agent/app/.env`) to prove the disjointness negate
defers rather than double-fires.

## Five gates (all clean, live `wazuh-logtest`)

```
Gate 1 (if_sid auto-parenting):   0 violations
Gate 3 (stock-ruleset collision): 0 violations   (child rule; no top-level collision surface)
Gate 2 (disjointness tally):      6/56 own-rule hits, deferred={'100101': 2}
Gate 4 (negate-on-absent-field):  0 violations
Gate 5 (FP vs 4,727 benign):      0 violations
Status ('validated'): passes all five gates  ->  validate-all: ALL CLEAN, 5 detections
```

## Measured numbers (reproducible)

| Tier | Command | sensitive_abs_read recall | Aggregate benign FP |
|---|---|---|---|
| Sample (public) | `make measure` | **2/3** (own-rule; the 1 overlap defers to 100101) | 0/4,727 |
| Full (licensed) | `make measure-full` | **6/8** (own-rule; the 2 overlaps defer to 100101) | 0/4,727 |

Technique-level, all 8 variants are detected (6 on `100109`, 2 correctly
deferred to `100101`) — reported as own-rule recall, not rounded up, the same
`2/3` / `6/8` discipline SAF-T1105 uses. `make measure-full` continues to
reproduce `docs/PHASE4-REPORT.md`'s original four techniques (12/12, 11/11,
11/11, 3/3) and the 0/4,727 aggregate FP unchanged; this technique's own number
is reported here, not asserted against PHASE4 (which predates it) — the same
treatment SAF-T1105 gets.

## Before / after (the D3 gap, closed)

Live `run_batch` against the ruleset with `100109` loaded:

```
100109  /etc/passwd                          (was 100100 / no alert)
100109  ~/.ssh/authorized_keys               (was 100100 / no alert)
100109  /proc/self/environ · /etc/ssh/sshd_config · /var/run/secrets/…/token
100101  /root/.ssh/id_rsa    -> defers (disjoint)
100101  /home/a/app/.env     -> defers (disjoint)
100108  ../../../etc/passwd  -> traversal owns it (disjoint)
100100  /app/sandbox/notes.txt, /app/workspace/README.md  -> no alert (benign, 0 FP)
```

## Known gaps (disclosed, not chased)

Registered in `detections/SAF-T1104_sensitive_abs_read/detection.yaml`: a
read tool advertised under any name other than `read_file`/`read_text_file`
evades (bounded tool-identity, same class as SAF-T1502 E5 / SAF-T1105's
negate-list); sensitive absolute paths outside the named list evade (bounded
named list); encoded/normalized paths evade (same class as SAF-T1105 E2–E4);
a symlink whose textual path looks benign is structurally invisible (same class
as SAF-T1105's symlink gap, unverified). None chased — the same
harden-vs-disclose policy as every other rule here.
