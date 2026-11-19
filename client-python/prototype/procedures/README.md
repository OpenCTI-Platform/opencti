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
warning (for example a report source that is not in the bundle). The import is
designed so that seeding the same file again creates no duplicates: procedure
ids are kept and the generated relationship ids are deterministic. This is not
verified on a live platform yet; verify it by seeding the file twice and
checking that the number of procedures in the Procedures list does not change.

## Seed the example library

`data/example-procedure-library.json` holds four more published procedures,
each in its own shape:

- an Ebury backdoor command (MITRE ATT&CK, T1059.004), used by Windigo, with
  its process and file observables and the Ebury malware;
- an in-memory PowerShell credential harvester (MITRE ATT&CK, T1059.001), used
  by Sandworm Team and the 2016 Ukraine Electric Power Attack campaign, with no
  observable because the source gives no command line;
- two Atomic Red Team tests for T1055.001, a mavinject DLL injection and a
  WinPwn SYSTEM shell, with their command and file observables, the WinPwn
  tool and a mitigating course of action.

The intrusion sets, malware, campaign and course of action carry their MITRE
ATT&CK ids and merge with the platform's MITRE data. URLs in command lines are
defanged.

```bash
python client-python/prototype/procedures/seed_procedures.py \
    --url http://localhost:4000 --token <token> \
    client-python/prototype/procedures/data/example-procedure-library.json
```

## Observables

A procedure's observables are `has-observable` relationships (procedure →
observable), the name used in the procedure white paper. On import,
`x_observable_refs` creates them; on export, `x_observable_refs` is rebuilt
from them, and a bundle export with relationships also carries the
relationship objects. They show as "has observable" links in an
investigation. The command (`x_command_ref`) and the sources
(`x_source_refs`) stay refs of the procedure.

Procedures saved before this change hold an older observable ref the platform
no longer reads: they cannot be exported or updated until that data is removed
and the procedures are imported again.

## Fingerprints

An imported `x_fingerprint` is kept as is and not checked against the
procedure's properties; the POWERSTAR value of the example bundle, for
instance, is not the one the formula gives. A missing fingerprint is computed
once, at creation, and never recomputed on edit. On import it is computed from
the technique ids as written in the bundle; in the UI, from the OpenCTI
standard ids of the attack patterns. The two are not comparable in this
prototype.

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

## Procedure heatmap

The techniques matrix of a campaign, intrusion set or threat actor can show how
many of its procedures implement each technique.

1. In Settings > Customization > Rules engine, enable "Usage propagation of
   procedure techniques" (and "Usage propagation via attribution", so an
   intrusion set also gets the procedures of the campaigns attributed to it).
   An entity using a procedure then also uses the techniques the procedure
   implements.
2. Open the entity, then Knowledge > Techniques, matrix view.
3. Turn on "Show procedure heatmap" in the matrix toolbar.

A technique is filled by its own procedure count. A parent technique whose
sub-techniques have procedures, but which has none itself, gets a coloured
border. Used techniques without procedures keep a neutral border. With the
example library, Windigo shows Unix Shell (T1059.004) filled and Command and
Scripting Interpreter (T1059) with a border.

## Customer samples

Customer procedure libraries are converted and seeded locally. They are never
committed to this repository, and neither are bundles made from them. Only the
generic example bundle is committed.
