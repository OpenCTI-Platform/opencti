# NIGHT-LOG — autonomous run of 2026-08-29

Working notes for the overnight run. Every decision is recorded here, with
the conservative default named whenever one was applied.

## Merge state at start

Read from `gh pr list` at the start of the run, before any branch was created.

| PR | branch | state at start | owner |
|---|---|---|---|
| #17884 | (merged) | MERGED 2026-08-29T01:32Z | — |
| #17945 | (merged) | MERGED 2026-08-28T23:53Z | — |
| #17976 | (merged) | MERGED 2026-08-29T01:57Z | — |
| #17946 | `fds/form-fields-night` | OPEN | another session — do not touch |
| #17977 | `fds/button-wrapper-wave` | OPEN | another session — do not touch |
| #17978 | `fds/iconbutton-naming-wave` | OPEN | another session — do not touch |
| #17979 | `fds/thaw-wave` | OPEN | another session — do not touch |

`design-system/current` tip at start: `3293449ee4`, pin `bd076e8f`.

## Base moved mid-run — #17946 merged

`#17946` merged into `design-system/current` while the Stage 1 worktree was
being prepared, and it carried a pin bump of its own.

- new tip: `f4e579200d`
- base pin after the merge: `0ed2581bf1b8a8cec5f5de654d94e4108703920c`
  (lib #186, the spacing scale in the delivered stylesheet)

The Stage 1 branch had no commits at that point, so it was reset onto the new
tip rather than rebased. **The pin was not walked back**: the bump now runs
`0ed2581 → 1f7c64c`, which is exactly the two lib commits this night is about:

- `8aaa846` — lib #189, Header integrated search + disabled field repainted as an outline
- `1f7c64c` — lib #190, Select clear control + Input `isTypeNumber` stepper

That is a narrower and cleaner bump than the one planned from `bd076e8f`
(14 commits): #186 arrived through the base instead.

## Stage 1 — the pin bump — PR #17980

Branch `fds/pin-bump-night`, one commit, four files: `package.json`,
`yarn.lock`, and the two regenerated bridge files.

`0ed2581 → 1f7c64c`. Every claim proven by bytes in the installed dist
(the greps are in the PR body). Two findings worth keeping:

1. **"padding-left 12px" is not universal.** It lands on Input, Textarea and
   the Combobox trigger. The **Select trigger deliberately keeps `pl-4`** —
   `dist/components/select/Select.mjs` still reads
   `h-9 w-fit … rounded-sm border pl-4 pr-2`. Recorded rather than smoothed
   over: a later "align the Select trigger too" is a design call, not a bug.
2. **The bump turned `[bridge-freshness]` red**, and the cause was benign:
   lib #190 appends an `@utility appearance-textfield` block to `theme.css`,
   moving the hash the gate reads. Regenerated with the documented command
   (AGENTS.md rule 1). Zero token values changed — the whole
   `fds-tokens.generated.ts` diff is its two hash lines.

Local gates before push: `check-ts` clean, `yarn test` exit 0 (11m56s),
conformity 38 checks / 0 issues, accessible-names clean.

**Conservative default applied:** the generator resolves the product as a
git-sibling directory, which a worktree pair is not. Rather than reach for
`--out-dir` (documented as a *testing* mechanism), a temporary symlink
`~/dev/opencti → ~/dev/night-pin` was created so the real
`--write-to-product` path ran, then removed. The bytes written are the
generator's own.

## Ownership amendment — #17979 transferred mid-run

Sandy transferred `#17979` (`fds/thaw-wave`) to this session while Stage 1 was
in CI. **Decision: superseded, not grown** — one of the two, never both open.

Reason it could not simply be rebased forward: `#17946` had already landed
almost all of it. Of its nine commits, one applied clean, one was dropped by
git as "already upstream", and the first — same title as `#17946`'s merge
commit — conflicted in four files. The rebase was abandoned in favour of a
merge, which measured the real remainder: **5 files, +21/−27**.

All 14 merge conflicts resolved to this branch's side, for one reason: the base
is **ahead** of #17979, not behind it. `EntitySelect`, `HiddenTypesField`,
`DataTableLine`, `FilterChipPopover`, `DataTableToolBar`,
`WorkspaceTurnToContainerDialog` and the two widget inputs were all converted
by #17946, so #17979's side of each hunk was the older MUI code. The pin was
**not** walked back.

## Stage 3 — what shipped, and every conservative default

### A — Select `clearable`: 1 of the 3 expected sites

Only **one** site is a `clearable` site. `ThemeForm` converted — FEEDBACK #45,
which names it as the single site and defines a removal test.

The other two the brief expected are **not** clearable sites:
`DashboardRelativeDateSelect` and `CustomViewPreviewEntitySelector` are blocked
on FEEDBACK **#43**, an OPEN DESIGN QUESTION Sandy reformulated on 2026-08-26
after visiting the live instance. The bump does not close it — it is hers.

Two further candidates found by grep, both **parked as arbitrations**:

- `Policies.tsx:264` — `<SelectItem value="">&nbsp;</SelectItem>`, an empty
  option row with no label. Replacing it with `clearable` is defensible (an
  option with no accessible name is a defect) but it removes a row from the
  panel, which is a UX call.
- `FormFieldRenderer.tsx:273` — `<SelectItem value=""><em>None</em></SelectItem>`.
  "None" is real, translated wording on a user-defined form schema, not an
  affordance stand-in.

### B — `isTypeNumber`: 1 site converted, the wide change PARKED for Sandy

The brief says "the 11 number fields". Measured: **101** `type="number"` mounts
across **50** files. Exactly **one** is a direct `<Input type="number">`
(`EntitySettingCustomFields.tsx:185`) — converted.

Every other one reaches the library Input through the `components/TextField.tsx`
pivot, which forwards `type` and would need **one line** to forward
`isTypeNumber` with it. That one line repaints ~100 fields across 50 files.
Parked deliberately: the intent ("native spinners gone") is unambiguous, the
**scale** is 9× what was authorised, and this is a visible change on most forms
in the product. The diff is in the morning report — it is a ten-second decision,
not a night-time guess.

Geometry checked: the stepper adds right padding inside the field
(`pr-7`, `pr-11` beside a state icon) and **no height**. The box does not move.

### C — TopBar → `HeaderSearch`: PARKED, with the note

Three things the top bar does have no expression in `HeaderSearchProps` /
`HeaderSearchMode`; the blocking one is that the NLQ toggle is a **split
button** and `HeaderSearchMode` renders one plain `<button>` per entry. Passing
the caret through `icon` is possible and is precisely the hack that was refused:
it nests an interactive element inside a button — the `nested-interactive` axe
failure the library itself avoided on the Select clear. Recorded as
LIBRARY-FEEDBACK **#54**, with a marker at the site. #17 and #20 stay open.

### D — closing conversions

Converted: `EntitySelect.tsx:100`, a display-only checkbox inside a Combobox
`renderOption` row — `checked` alone, iso with the pattern #17946 already
merged elsewhere.

**Parked, and this is the largest single decision of the night: the 86 direct
Switch sites.** Measured, not estimated: **77 of 86 sit inside a
`FormControlLabel`**, across 31 files (`FormSchemaEditor.tsx` alone holds 31).
Three reasons together, all in CENSUS-FINAL.md: the clone-injection trap that
broke a consent checkbox in #17946 has to be read per site; row height goes
38px → 20px on ~30 more forms; and the 9 sites outside a `FormControlLabel`
carry compensations (`Experience.tsx`: `marginBlock: -0.75`, a −6px pull that
exists only to cancel MUI's padding box) that must come off with them. A
partial pass leaves 20px and 38px switch rows on the same screen — worse than
none.

Also parked, same shape: the 3 Radio and 6 of the 9 remaining Checkbox sites,
all inside `FormControlLabel`. `FilterChipPopover.tsx:400` is **untouched by
rule** — `CENSUS.md` names that exact checkbox as the suspect in a parked E2E
red.

### Gates local to the branch

`check-ts` clean · conformity **41 checks / 0 issues** · accessible-names clean
· `check:utility-classes` clean.

The accessible-names gate earned its keep: it caught `SelectContent` with no
`aria-label` in the converted ThemeForm — an unnamed listbox — before push.

`.capitalize` is **not** in the delivered CSS (checked before writing it), so
the three `textTransform` declarations stay inline styles rather than becoming
silently dead utility classes.

## CI

Both PRs finish **45 pass / 0 fail / 0 pending**, with all four E2E job pairs
present on both the `push` and the `pull_request` run — the strict criterion,
met.

### The one red of the night, and how it was settled

`Backend / Integration tests` failed on **both** runs of #17980's first SHA.
Diagnosed rather than assumed, and the deciding evidence is that the two runs
of the **same SHA failed on different tests**:

| run | failing test |
|---|---|
| `push` | `telemetryManager-test.ts > shared saved filters count and permission changes are collected` |
| `pull_request` | `customView-resolvers-test.ts > telemetry > gauges are updated` |

A real red falls twice in the same place. `gh run rerun --failed` on both,
**no code change**: both went green.

**Then a docs-only commit on #17981 turned the same job red a third time, on a
third distinct test** — `ingestion-csv-resolver-test.ts > should reset state of
CSV feeds ingester`, which is not a telemetry test at all.

That last one corrects the diagnosis rather than confirming it. The first
narrowing — "process-global telemetry meters, the absolute-count shape
`CENSUS.md` records for `Dashboard CRUD`" — was too specific. Four
`Backend / Integration` runs across this stack produced **four different
failing tests in three unrelated suites**, one of them on a commit that changes
only a markdown file. The honest statement is broader: **the integration suite
is currently flaky through shared state and ordering, not in one subsystem**.

| run | failing test |
|---|---|
| #17980 `push` | `telemetryManager-test.ts > shared saved filters count…` |
| #17980 `pull_request` | `customView-resolvers-test.ts > telemetry > gauges are updated` |
| #17980 both, re-run | *(green, no code change)* |
| #17981 `push` (docs-only commit) | `ingestion-csv-resolver-test.ts > should reset state of CSV feeds ingester` |

What stays solid: none of these is reachable from this stack's diff. #17980
touches four files under `opencti-front`; the commit that produced the third
failure touches one `.md`. The base `f4e5792` is green on the same job.

**Expect this to recur on the merges.** It is not something this stack can fix,
and it is worth its own issue: a green `Backend / Integration` here is currently
a coin flip, which is exactly the condition under which a real red gets waved
through.

Worth knowing for next time: `gh run rerun` is refused while the workflow is
still running, so the re-run has to wait for the whole run to finish, not just
the failing job.
