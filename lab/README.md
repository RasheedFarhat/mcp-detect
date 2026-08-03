# MCP Detect lab components

This directory contains the operational pieces used to generate, capture, and
analyze MCP traffic. Commands are run from the repository root so paths remain
consistent between the host and Docker lab.

| Component | Purpose |
|---|---|
| [`agent/`](agent/) | Container image for the local LLM-backed MCP agent |
| [`client/`](client/) | Deterministic client used by the smoke path |
| [`proxy/`](proxy/) | Byte-transparent JSON-RPC capture and telemetry enrichment |
| [`schema/`](schema/) | Telemetry JSON Schema, specification, and validator |
| [`corpus/`](corpus/) | Benign task set, agent loop, fixtures, and summarizer |
| [`attacks/`](attacks/) | Synthetic attack and evasion harnesses |
| [`baseline/`](baseline/) | Stateful trust-on-first-use drift detector |
| [`analysis/`](analysis/) | Live Wazuh measurement and report generators |
| [`redaction/`](redaction/) | Local telemetry minimization and validation |

Start with `make measure` for the offline evidence path or follow
[`docs/REPRO.md`](../docs/REPRO.md) for the Docker/Wazuh lab.
