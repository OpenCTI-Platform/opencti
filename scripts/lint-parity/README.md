# ESLint / oxlint parity check

oxlint runs next to ESLint in `opencti-front` and `opencti-graphql`. ESLint
stays the linter that decides whether a change is correct. oxlint runs in
shadow mode, and this folder holds the script that compares the two.

## Why oxlint

- Speed: on `opencti-front`, `yarn lint:ox` takes about 4 s and ESLint (cold,
  no cache, type-aware) about 85 s on a developer laptop.
- One native binary, distributed through npm.
- `@oxlint/migrate` converts an ESLint config to an oxlint config, which lets
  us generate `.oxlintrc.json` instead of maintaining a second config by hand.

### Why not Biome

Facts from Biome's own documentation:

- Its rule sources page (https://biomejs.dev/linter/rules-sources/) lists ESLint
  core, `typescript-eslint`, `eslint-plugin-import`, `eslint-plugin-jsx-a11y`
  and `eslint-plugin-react` among its sources, as a mapping of selected rules,
  not full coverage: the `eslint-plugin-import` table has four entries. The
  page also notes that Biome rules may have fewer options than the originals.
- `biome migrate eslint` (https://biomejs.dev/guides/migrate-eslint-prettier/)
  ports an ESLint config, but by default only rules identical to their ESLint
  source, and the page says some options are not implemented and some rules
  deliberately differ.
- Biome plugins use Biome's own API: GritQL, or JavaScript plugins in developer
  preview (https://biomejs.dev/linter/plugins/). The page does not describe
  running ESLint plugins.

So a move to Biome would be a partial, rule-by-rule replacement of the ESLint
config. oxlint with `@oxlint/migrate` generates its config from our ESLint
config, which is what lets us measure parity rule by rule.

## Why shadow mode

Switching linters changes what passes in CI. Running oxlint beside ESLint and
diffing the findings tells us, rule by rule and line by line, where oxlint
differs, before anything depends on it. Nothing about `yarn lint` changes.

Phases:

1. Phase 1 (this change): a CI step per package runs `yarn lint:parity` with
   `continue-on-error: true`. The report is in the job log, the build never
   fails because of it. The PR lands with an empty report: every remaining
   difference is triaged in `lint-parity.json`.
2. Phase 2 (later, separate PR): once the report is clean on `master`, remove
   `continue-on-error`. A parity regression then blocks merges, while ESLint
   still decides correctness.
3. Switching oxlint to the blocking linter is out of scope here.

## How to run

From `opencti-platform/opencti-front` or `opencti-platform/opencti-graphql`:

| Command | What it does |
|---|---|
| `yarn lint:parity` | Runs ESLint (warnings included, no `--quiet`, no cache) and oxlint, compares findings, prints the report. |
| `yarn lint:ox` | Runs oxlint alone with `.oxlintrc.json`. Informational. |
| `yarn lint:ox:sync` | Regenerates `.oxlintrc.json` from `eslint.config.ts` and prints what could not be carried over. |

Exit codes of `lint:parity`: `0` parity, `1` differences remain (or a stale
allowlist entry, or the two tools checked a different number of files), `2`
tool or config error (a tool crashed, produced no output, or checked no files).

Never hand-edit `.oxlintrc.json`: it is generated and the next sync overwrites
it. If the generated config needs a fix, make it in the post-processing of
`sync.mjs`, then run `yarn lint:ox:sync` and commit the result.

`oxlint` and `@oxlint/migrate` are pinned to the same exact version, in both
packages. Bump them together, then run `yarn lint:ox:sync` and `yarn lint:parity`
in both packages.

In `opencti-front`, ESLint is type-aware and reads the gitignored relay
`__generated__` files. Run `yarn build` (or `yarn relay`) once before
`yarn lint:parity` locally, otherwise ESLint reports differences that are not
oxlint's fault. CI runs the step after "Frontend install and build".

The script's own tests: `node --test "scripts/lint-parity/test/*.test.mjs"` from the repo root.

## How to read the report

The first line is `parity: OK` or `parity: DIFFERENCES`.

- `files: eslint N, oxlint M`: printed right after `parity: DIFFERENCES` when
  the two tools checked a different number of files. This alone makes the exit
  code `1`, even with no finding differences (the finding report is then left
  out). It usually means the two tools see a different file set (ignore
  patterns, `.gitignore`, a missing `__generated__` folder). Fix that first.
- Summary table (plain text, `rule | only eslint | only oxlint | severity
  mismatch`, printed only when there are differences): one row per rule.
- Details, listed as `file:line rule` (paths are relative to the package,
  POSIX style). Each group shows at most 50 lines, then `… and N more`, so a
  long list in the CI log is truncated:
  - Only ESLint: ESLint reports it, oxlint does not. oxlint misses something
    (rule not enabled for that file by an override, option not carried over,
    behavior difference). A rule absent from `.oxlintrc.json` altogether is
    not listed here, see "skipped" below.
  - Only oxlint: oxlint reports it, ESLint does not. oxlint is stricter, or wrong.
  - Severity mismatch: both report it, one as an error and the other as a warning.
- "ESLint-only findings skipped": findings of rules that are not compared,
  either because the package lists them in `eslintOnly` or because oxlint has
  no such rule enabled in `.oxlintrc.json` (for example `custom-rules/*`).
  The counts are informational and do not affect the exit code.
- "Stale allowlist entries": allowlist entries that match no remaining
  difference. Remove them. They make the exit code `1`.

Findings are compared as multisets on file, line and rule (not column): the
same rule twice on one line counts twice. Diagnostics with no rule id (parse
errors, unused `eslint-disable` reports) are dropped.

## Recording a known difference

Each package has a `lint-parity.json`:

```json
{
  "eslintOnly": [{ "rule": "some/rule", "reason": "..." }],
  "allowlist": [{ "rule": "some/rule", "files": "src/some/file.ts", "reason": "..." }]
}
```

- `eslintOnly`: rules oxlint cannot run (or runs only partly). ESLint findings
  for them are not compared.
- `allowlist`: known differences for a rule that is compared. `files` is
  optional.
- `reason` is mandatory on every entry, and must say why oxlint cannot match
  ESLint (ideally with a minimal repro).

Policy:

1. Fix the config first: enable the rule, set the option, fix the sync
   post-processing. Add an entry only when oxlint cannot express the ESLint
   behavior.
2. Prefer a file-level entry (`files` set) over a rule-level one. A rule-level
   entry hides every difference of that rule, including new ones.

Details of how entries match:

- `files` is one glob string, not an array. It is matched with
  `path.matchesGlob` against the package-relative POSIX path of the finding.
  `**` does not match dotfiles.
- Allowlist entries match in both directions: an entry hides only-oxlint and
  only-ESLint differences (and severity mismatches) for that rule, in the files
  it covers. A rule-level entry added for an oxlint-only difference also hides
  only-ESLint differences of the same rule.
- `typescript-eslint` rules that oxlint folds into core rule ids are written
  with the core id: `no-unused-vars`, not `@typescript-eslint/no-unused-vars`.
  The list is `TYPESCRIPT_FOLDED_RULES` in `normalize.mjs`. Re-check it when
  bumping `@oxlint/migrate`.
