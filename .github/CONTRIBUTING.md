# Contributing to MCP Detect

Thank you for helping make MCP security evidence more reproducible.

## Before opening a change

- Use synthetic or explicitly redistributable data only.
- Do not include customer traffic, access tokens, private keys, personal data,
  or exploit evidence obtained without written authorization.
- State what a detection can observe and what it cannot establish.
- Add or update a fixture for behavioral changes.
- Never improve a metric by relabeling or silently removing a difficult case.

## Development

MCP Detect's offline framework is dependency-free on Python 3.11+.

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
make measure
make test
make verify
```

Changes to `wazuh/local_rules.xml` invalidate the pinned golden files by design.
Refresh goldens only with the live Wazuh stack, review the semantic diff, and
explain the measurement change in the pull request.

## Detection contributions

A new detection should include:

1. A `detections/<technique>/detection.yaml` definition.
2. A concrete observable tied to the threat model.
3. Positive, negative, and evasion-oriented fixtures.
4. Known gaps and compensating controls.
5. Reproducible expected evidence.

Small, focused pull requests are easiest to review. Opening an issue first is
recommended for schema or public-interface changes.
