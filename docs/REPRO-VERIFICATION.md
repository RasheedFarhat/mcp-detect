# Reproduction verification

MCP Detect exposes both its fast sample and complete synthetic corpus in the
public repository. Neither offline reproduction path requires Docker, Wazuh,
credentials, or a pre-existing virtual environment.

| | Fast sample | Complete corpus |
|---|---|---|
| Command | `make measure` | `make measure-full` |
| Attack input | `data/attack_corpus_sample_v1.jsonl` | `data/full/attack_corpus_full_v1.jsonl` |
| Benign input | `data/benign_corpus_v2.jsonl` | Same |
| Expected evidence | Sample expected-numbers file | Published Phase 4 report |
| Infrastructure | None | None |

## What the offline replay proves

The committed golden-match files contain final rule identifiers previously
captured from genuine `wazuh-logtest` batch runs. The replay feeds those frozen
verdicts into the same coverage aggregation used by the live pipeline.

Every golden file records the SHA-256 of `wazuh/local_rules.xml`. The replay
recalculates that hash and refuses to run if the rules have changed. This makes
stale evidence a loud failure instead of silently attributing old results to a
new rule set.

The replay proves that the published calculations are reproducible from the
committed evidence. It does **not** prove that a currently running Wazuh engine
will produce identical verdicts, that project-authored fixtures represent the
outside world, or that an MCP deployment is secure.

## Verify the live engine

With Docker available:

```sh
make lab-up
python3 framework/repro_offline.py --capture-golden --tier sample
git diff -- data/attack_corpus_sample_v1.golden_matches.json
python3 framework/parity_check.py
```

An empty semantic diff confirms that the local live engine reproduced the
committed sample verdicts. `parity_check.py` independently checks current live
results against the frozen reports.

The stack is a local development lab with development credentials. Do not
expose it to an untrusted network.

## Additional release verification

```sh
make test
make check-sample
make verify
```

`make verify` runs both corpus tiers, the framework regressions, the proxy and
baseline tests, redaction safety tests, the synthetic evidence-manifest check,
and the cross-tenant authorization retest.
