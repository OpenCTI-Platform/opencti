# Selection-field census

Regenerate:

```bash
node fds-migration/scripts/census-selection-fields.mjs opencti-platform/opencti-front/src
```

## Method, and why the earlier counts were wrong

The script resolves the **local name** of every imported symbol per file, then
counts usages of that local name. Matching on the element name is what broke two
earlier counts: one missed `import Select from '@mui/material/Select'` (37
mounts), the next missed the aliased and default-plus-named forms (14 more).
Aliases in this codebase: `MUIAutocomplete`, `MuiAutocomplete`, `MuiSelect`. A
library `Select` block is excluded by the presence of `<SelectTrigger>`.

```bash
node fds-migration/scripts/census-selection-fields.mjs opencti-platform/opencti-front/src
```

## Totals

| | mounts |
|---|---|
| Converted — Formik pivots (`SelectFieldFds` / `ComboboxField`) | 157 |
| Converted — direct library composition | 129 |
| **Converted total** | **286** |
| **Remaining on MUI** | **6** |
| **Total selection fields** | **292** |

The denominator is derived, not fixed: a site converted onto a Formik pivot
counts as its own mount, while a site on a legacy adapter counts once at the
adapter file. Parking a site therefore lowers both numerator and denominator.

## The 6 remaining

| file | reason | blocked or convertible |
|---|---|---|
| `components/AutocompleteField.tsx` | the legacy MUI adapter; 2 consumers left (`LocationField`, `StixCoreObjectsField`) | **blocked** — must outlive its consumers |
| `components/fields/SelectField.tsx` | the legacy MUI adapter; 4 consumers left (`AuthorizedMembersField` + list item, `StixCoreObjectFilesAndHistory`, `JsonMapperRepresentationAttributeForm`) | **blocked** — same |
| `components/dashboard/DashboardRelativeDateSelect.tsx` | FEEDBACK #43 — the field tints itself while it constrains the view; no library equivalent | **blocked on the library**, V2 |
| `settings/sub_types/custom_views/CustomViewPreviewEntitySelector.tsx` | FEEDBACK #43, same gap | **blocked on the library**, V2 |
| `settings/themes/ThemeForm.tsx` | FEEDBACK #45 — the Select must be emptiable. Verified at pin `bd076e8f`: `clearable` is declared on Combobox only, never on Select | **blocked on the library**, V2 |
| `components/filters/FilterChipPopover.tsx` | converted, then parked on a deterministic E2E red — see below | **convertible, cause not established** |

### Why FilterChipPopover is parked

`group0` "Add a new filter in the observables list" and `group1` "background
tasks pre-requisites on incident search" both failed with

```
locator.check: Clicking the checkbox did not change its state
```

on an option row inside the listbox named "Label" — this component's value
picker. Deterministic: the same error in both runs of the A/B, on two
consecutive heads.

Read from the failure artefact, not inferred: `getByLabel('background-task')`
resolves to a `generic` (the span inside the Tooltip that replaced MUI's `<li>`)
and the post-failure snapshot shows the option already `[selected]` with its
checkbox `[checked]`. The selection lands, but outside the window Playwright's
`check()` verifies. That points at a controlled MUI `Checkbox` inside a
library-owned row, not at the change handler.

Whoever resumes it: start there, and note that the handler also needed MUI's
`reason` derived from the value delta, because the library reports removing one
chip as `clear`, exactly as it reports emptying the field.

## Verified against the pin `bd076e8f`

- **#155 is present**: `ComboboxField` declares `startIcon` (presentational,
  always `aria-hidden`) and `adornment` (host-owned, keeps its own pointer and
  focus behaviour). No bump was needed for the adornment sites.
- **#45 is absent**: `clearable` exists on Combobox only.

## The width rule

`SelectTrigger` ships `w-fit`, so a converted Select shrank to its content where
the MUI original filled its container. `ComboboxField` ships `w-full`, so
Combobox conversions were never affected — this was a Select-only defect.

- `SelectFieldFds` honours `fullWidth` and puts `w-full` on the trigger; 94 of
  its 102 call sites pass it.
- 62 direct triggers carry an explicit width read from the MUI original at the
  merge base.
- 3 stay at `w-fit` deliberately (`ListCards`, `AISummaryContainers`,
  `StixDomainObjectHeader`): their base FormControl declared no width.

## Accessible names

`fds-migration/scripts/check-accessible-names.mjs`, four rules, wired into the
frontend quality job in CI. Rule 1 was dead until the review round — its aria
test scanned the whole `<Select>` block, so the `aria-label` the panel rule
mandates satisfied it; scoping it to the trigger's own opening tag revived it and
immediately found two sites it had been hiding.

## Out of scope

- `SearchField` — belongs to the library, reaches the products at a future bump.
- The mass-actions toolbar chips — tooling chips, not select fields. Owner: the
  button/chip wave.

## Not verified at the pointer

- The two EE-gated `ConnectorsStatusFilters` mounts: behind
  `isEnterpriseEdition`, unreachable on this instance. Typechecked and
  lint-clean only.
- The five multi-value Comboboxes and the width changes: proven by tsc, lint and
  the guard, not by a click.

## `Dashboard CRUD` is flaky, and this repo gives a free A/B

Its later assertions check absolute counts after filling absolute dates. The
same tree failed one run and passed another, and successive failures stopped on
different assertions (29, 17, 36).

`ci-main.yml` fires on both `pull_request` and `push`, so every SHA gets two
runs. They are only comparable when the base has not moved — the `pull_request`
run checks out `refs/pull/N/merge`, the `push` run the branch SHA. Check with
`git merge-base --is-ancestor origin/design-system/current HEAD` before drawing
any conclusion from a divergence.
