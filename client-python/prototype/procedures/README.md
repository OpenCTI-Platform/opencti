# Procedure prototype: seed data

Scripts to load procedures (STIX `x-opencti-procedure`) onto a platform for
the Procedure entity prototype. They live here, and not under `examples/`,
because `examples/run_all.sh` runs every script in `examples/` in CI.

## Prerequisites

- A platform running the feature branch, reachable with an API token.
- The MITRE ATT&CK dataset loaded on that platform. A procedure implements
  attack patterns that are not part of its bundle; they resolve against the
  platform's MITRE data.
- The local, editable pycti, not the released one. Only this version converts
  `x-procedure` bundles:

  ```bash
  pip install -e client-python
  ```

## Where the conversion runs

The `x-procedure` conversion (type and id rename, techniques, vulnerabilities,
tactics and report sources) runs only on the pycti paths: the seed script, the
connector helper and any client that splits bundles with pycti. Platform-side
ingestion (TAXII, feeds, bundle push, sync, playbooks) does not convert
`x-procedure` in this prototype. A procedure that reaches the import
unconverted is imported with a warning naming what is lost, and its platforms
are lowercased.

## Seed the example bundle

`data/example-procedures.json` holds a POWERSTAR procedure published as
`x-procedure`, the intrusion set, malware, indicator and identity its
relationships point to, and a second procedure with an observable, a
vulnerability and a report source.

```bash
python client-python/prototype/procedures/seed_procedures.py \
    --url http://localhost:4000 --token <token> \
    client-python/prototype/procedures/data/example-procedures.json
```

The script prints the number of objects imported by type and any normalizer
warning (for example a report source that is not in the bundle). Seeding the
same file again does not create duplicates.

## Generate procedures at scale

```bash
python client-python/prototype/procedures/generate_scale_bundle.py \
    --url http://localhost:4000 --token <token> \
    --mitre-id T1059.001 --mitre-id T1566.001 --count 500 \
    --out /tmp/scale.json
python client-python/prototype/procedures/seed_procedures.py \
    --url http://localhost:4000 --token <token> /tmp/scale.json
```

Each MITRE id is resolved to the attack pattern of the platform. `--count`
procedures are generated per attack pattern, named `[Verb] [Object] via
[Tool/Method]`. The same `--seed` and MITRE ids give the same bundle;
procedure ids also depend on the attack pattern, so another MITRE id with the
same seed gives other procedures.

## Customer samples

Customer procedure libraries are converted and seeded locally. They are never
committed to this repository, and neither are bundles made from them. Only the
generic example bundle is committed.
