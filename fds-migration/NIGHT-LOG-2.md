# NIGHT-LOG-2 — autonomous run of 2026-08-30

Follow-up to Sandy's final visual pass on the deployed stack (`:3000`).
Every parked item is recorded here with the reason it was parked, so the
morning decision is a choice and not an archaeology exercise.

Issue: #17989. Base: `design-system/current` @ `a9c5027b39` (the #17984
merge). Library pin `47baf69`.

## Premises checked before any code

- **#17983 and #17984 are both merged**, as the brief states. Worth a note
  because their commit subjects carry the umbrella issue `(#17926)`, not
  their own PR numbers, so grepping the log for `#17983` finds nothing and
  looks alarming. `a9c5027b39` IS #17984's merge commit and IS the tip.
- **The pin really carries #188, #189, #190 and #191** — each verified as
  an ancestor of `47baf69`, not taken from the changelog.
- **The build Sandy reviewed was current.** `dist/` was built at 18:50,
  after the 18:41 pin bump, and its CSS carries `--depth-sm` from #188.
  The two commits that follow are documentation only. So none of her
  feedback is stale against the pin — a real risk, since #17983 and
  #17984 both merged *after* that build (22:53 and 23:17).

## Parked, with the diagnosis

### Datatable vertical centring — NOT a datatable bug

The pass asks to "check tous les datatables". The datatable is already
right: `DataTableLine` centres both its cell container and its cell.

The screen actually named — Localisation / Pays — does not use it. It uses
the legacy `ListLines`, whose cells come from a `bodyItem` style that is
**copy-pasted into 75 line components** (59 of them with `height: 25`
inside a 50px row, and no vertical centring). That is why the defect looks
like it is everywhere: it is one style, duplicated 75 times.

Parked because the fix is a decision, not a patch: either one shared style
(or a library cell) that all 75 files consume, or 75 identical edits that
no reviewer can meaningfully read. `float: left` in the same rule also
fights `align-items`, so it is not a one-line change even per file.

### Two icon groups cannot convert — LIBRARY-FEEDBACK #56

`ContainerHeader` and `StixCoreObjectContentHeader` render their items as
router `Link`s. `ButtonGroupItem` is a plain `<button>` with no `asChild`
and no `as` — verified in the installed build, not the types. Converting
would silently drop href semantics: middle-click, open-in-new-tab, the
hover target, the link role. Listed rather than forced, per the migration
contract.

### Text-bearing toggle groups

`ButtonGroupItem` takes an `icon` and a required `aria-label` and renders
no text at all. `ToggleButtonField` and
`StixDomainObjectAttackPatternsKillChain` are text toggles, so they have
no library counterpart today. Not a gap worth a PR until a designer says
the library should carry text items.

### Still open from the pass, not started

Number inputs, the remaining selects (including the cut-off alias-modal
select), textareas, the whole of PR 2 (outlined + library background,
drawer repaint, integration Paper) and the whole of PR 4 (right-nav below
the tabs). Nothing was half-applied: these are untouched, not partly done.

## One behaviour change, deliberate

`ViewSwitchingButtons` carried **no `onChange` on the MUI group at all**,
and only its "lines" item had an `onClick`. With the props Narratifs
passes, `subEntityLines` therefore rendered and did nothing. The library
group takes `onValueChange` on the group rather than per item, so wiring
it the only way it can be wired revives that button.

That is a fix, but it IS a change in what the screen does, so it is
flagged here and in the PR body rather than buried in a diff.

## Local test note

`src/utils/Time.test.ts` fails on this machine and passes under `TZ=UTC`.
It asserts `09:30` against a UTC input while the machine runs at UTC+2. No
relation to this work — the file was never touched — and CI runs UTC.
