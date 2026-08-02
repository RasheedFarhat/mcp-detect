# State of MCP Detect

**Updated:** 2026-08-02

MCP Detect is an open-source detection-engineering lab. Its code, rules,
documentation, fixtures, sample corpus, and complete self-authored corpus are
published under MIT.

## What works

- A byte-transparent stdio proxy captures MCP JSON-RPC traffic as JSONL.
- The telemetry schema and validator cover the captured event format.
- Ten Wazuh rules plus two parent anchors detect five structural techniques.
- A stateful baseline watcher detects server and tool-definition drift.
- The Detection-as-Code framework validates definitions, compiles rules,
  measures coverage, inventories servers/tools, and records known gaps.
- Offline replay refuses golden evidence whose pinned rule hash is stale.
- The fast and complete corpus tiers reproduce from committed public files.
- The synthetic cross-tenant example includes vulnerable source, an exact fix,
  and executable denied retests.

## Current measured evidence

- Complete attack scenarios: 12/12, 11/11, 11/11, and 3/3 for the four
  original scenario groups documented in the Phase 4 report.
- Benign corpus: zero alerts across 4,727 records and 541 sessions.
- These results use self-authored synthetic traffic and are regression evidence,
  not independent accuracy validation.

## Known limits

- Telemetry indicators cannot prove handler-level or downstream authorization.
- Behavior-only compromise can look legitimate at the protocol layer.
- Encoding and Unicode confusables can evade literal structural matches.
- Wazuh cannot express every stateful or semantic relationship needed here.
- The local stack is a research environment, not a hardened deployment.
- No independent corpus has yet established external validity.

## Next evidence priorities

1. Add independently authored or held-out traffic with explicit provenance.
2. Keep live-engine captures and offline goldens pinned and reproducible.
3. Add new detection techniques only with a defensible observable and fixture.
4. Publish concise boundary notes connecting architecture, trust decisions,
   failure modes, and defensive tests.
