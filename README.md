# MCP Detect

**An open-source detection-engineering lab for Model Context Protocol abuse.**

MCP Detect captures MCP JSON-RPC traffic as structured telemetry, evaluates it
with Wazuh rules and stateful detectors, and measures the results against frozen,
labeled corpora. The repository includes the complete self-authored dataset,
reproduction tooling, known blind spots, and a synthetic authorization case
study.

This is a research lab, not a production monitor, enforcement gateway,
certification, or claim that an MCP deployment is secure.

## Reproduce the evidence

From a clean clone, with Python 3.11 or newer:

```sh
make measure
```

That command replays committed `wazuh-logtest` verdicts against the public
sample corpus. To reproduce the complete published measurement:

```sh
make measure-full
```

Both paths are offline, require no credentials, and use only files in this
repository. See [REPRO-VERIFICATION.md](REPRO-VERIFICATION.md) for exactly what
the replay proves and what still requires a live Wazuh run.

## Architecture and trust boundary

```text
MCP client ──▶ transparent proxy ──▶ MCP server ──▶ downstream resource
                    │
                    ▼
              telemetry.jsonl
                    │
          ┌─────────┼──────────┐
          ▼         ▼          ▼
      Wazuh rules  stateful   inventory and
                   drift      coverage tools
```

The proxy forwards traffic unchanged and records one JSONL event per JSON-RPC
message. Stateless rules detect structural indicators. The baseline watcher
detects definition drift across sessions. Framework tools compile detection
metadata, join alerts, calculate coverage, and refuse stale offline evidence
when the pinned rule hash changes.

The telemetry layer can observe what identity and arguments reached a handler.
It cannot, by itself, prove that the handler correctly enforced tenant ownership
or downstream authorization. The synthetic
[cross-tenant reference](samples/reference-mcp-review/README.md) demonstrates
that boundary with vulnerable source, an exact fix, and a denied retest.

## Current detections

| Technique | Signal | Implementation |
|---|---|---|
| Tool poisoning | Hidden instructions in advertised tool descriptions | Wazuh |
| Credential exposure indicators | Sensitive reads or secret-shaped arguments | Wazuh |
| Sensitive absolute-path read | Credential or system paths passed to file tools | Wazuh |
| Path traversal | `../`-style escape attempts | Wazuh |
| Rug pull | Server or tool definitions changing after trust is established | Stateful baseline |

The full self-authored corpus reproduces **12/12, 11/11, 11/11, and 3/3**
scenario results with **0 alerts across 4,727 benign records / 541 sessions**.
Those are regression results against project-authored traffic, not independent
accuracy claims.

## Honest limitations

- All included malicious and benign telemetry is synthetic and self-authored.
- Telemetry cannot establish semantic intent or prove downstream authorization.
- Encoded exfiltration, homoglyph instructions, and behavior-only compromise can
  evade these structural signals.
- Offline replay proves reproducibility of frozen engine verdicts; live parity
  requires the Docker/Wazuh path.
- A clean run means only that the implemented checks found no matching
  indicators.

The current evidence ledger is [docs/STATE-OF-PROJECT.md](docs/STATE-OF-PROJECT.md).

## Repository map

- `proxy/` — byte-transparent MCP stdio proxy and telemetry capture.
- `schema/` — JSON Schema and validator for telemetry records.
- `detections/` and `wazuh/` — detection definitions and Wazuh rules.
- `baseline/` — stateful trust-on-first-use drift detection.
- `framework/` — compiler, registry, coverage, inventory, and verification tools.
- `attacks/` and `corpus/` — synthetic traffic generators and fixtures.
- `data/` — sample, benign, evasion, and complete attack corpora.
- `samples/reference-mcp-review/` — synthetic cross-tenant defect, fix, and retest.
- `northwindpay/` — synthetic worked telemetry example.
- `docs/` — design decisions, engine findings, reports, and research history.

## Verification commands

```sh
make measure          # fast sample replay
make measure-full     # complete public corpus replay
make test             # offline framework regression suite
make check-sample     # verify the synthetic NorthwindPay artifacts
```

The proxy's JSON Schema assertion uses the optional test dependency:

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
make verify           # consolidated offline release check
```

The local Docker lab is intentionally configured for development credentials
and loopback access. Do not expose it to an untrusted network or treat it as a
production deployment. Live-engine instructions are in
[docs/REPRO.md](docs/REPRO.md).

## Contributing and security

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before
submitting a rule, corpus fixture, or framework change. Report suspected
vulnerabilities through the private process in [SECURITY.md](SECURITY.md).

MCP Detect was created and is maintained by
[Rasheed Farhat](https://github.com/RasheedFarhat). If you use the project in
research, see [CITATION.cff](CITATION.cff).

## License

MIT. The license covers the original code, rules, documentation, fixtures, and
complete synthetic corpus in this repository. See [LICENSE](LICENSE).
