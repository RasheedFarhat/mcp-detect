# corpus/fixtures/ — synthetic false-positive boundary probes

**Nothing in this directory (or its subdirectories) is a real secret, key, or
credential.** Every file here is a synthetic fixture, deliberately named and
placed to *look* trigger-adjacent to a naive, over-broad sensitive-file
detection rule, while being legitimately benign content. They exist so the
benign corpus can populate the false-positive boundary of Wazuh rule 100101
(`docs/PHASE0.md`, `wazuh/local_rules.xml`) instead of staying comfortably far
from it — see `corpus/tasks.py`'s module docstring and
`data/benign_corpus_v2.summary.md` for the full rationale.

Concretely, do not mistake:

- `keys/` for a directory containing real cryptographic keys. It contains one
  markdown file explaining why the directory exists (this quarantine note),
  nothing else, ever.
- `example.env.txt` for a real `.env` file. Its name contains the substring
  `.env` but it does **not** end in `.env` (it ends in `.txt`) — that's the
  point: it must not match rule 100101's anchored pattern
  (`(?i)(\.env$|id_rsa$|\.aws/credentials$)`), and every value inside it is a
  placeholder.
- `config/app_settings.json` for a real application config with secrets. It's
  three harmless UI preference keys and a note explaining itself.

All three were verified against the actual rule regex before use (see
`docs/PHASE1b.md`) — they correctly do **not** match, the way a well-scoped
rule should treat them, in contrast to the real (also synthetic) sensitive
fixtures planted for `make smoke` (`sandbox/.env`, `sandbox/id_rsa`), which
correctly **do** match.

If you are extending this corpus and adding more boundary probes, keep them
here, keep them obviously synthetic in content, and add a one-line comment
in the file itself (like the existing three) stating why it's safe.
