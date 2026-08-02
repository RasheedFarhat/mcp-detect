#!/usr/bin/env python3
"""Validate a JSONL telemetry log against schema/schema.json. Exits non-zero on any invalid record."""
import json
import sys
from pathlib import Path

import jsonschema


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <telemetry.jsonl>", file=sys.stderr)
        return 2

    schema_path = Path(__file__).parent / "schema.json"
    schema = json.loads(schema_path.read_text())
    validator = jsonschema.Draft202012Validator(schema)

    n_ok = 0
    n_err = 0
    for line in Path(sys.argv[1]).read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        errors = list(validator.iter_errors(record))
        if errors:
            n_err += 1
            print(f"INVALID: method={record.get('method')} errors={[e.message for e in errors]}")
        else:
            n_ok += 1

    print(f"{n_ok} records valid, {n_err} invalid")
    return 1 if n_err else 0


if __name__ == "__main__":
    sys.exit(main())
