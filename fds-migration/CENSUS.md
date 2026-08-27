# Selection-field census

Regenerate:

```bash
node fds-migration/scripts/census-selection-fields.mjs opencti-platform/opencti-front/src
```

## Method, and why the earlier counts were wrong

The script resolves the **local name** of every imported symbol per file, then
counts usages of that local name. Matching on the element name is what broke the
two previous counts:

| import form | earlier pattern | now |
|---|---|---|
| `import { Select } from '@mui/material'` | matched | matched |
| `import Select from '@mui/material/Select'` | matched | matched |
| `import Select, { SelectChangeEvent } from '@mui/material/Select'` | **MISSED** — the pattern required `Select` immediately before `from` | matched |
| `import MUIAutocomplete from '@mui/material/Autocomplete'` | **MISSED** — matched on `<Autocomplete`, never on the alias | matched |

Aliases in this codebase: `MUIAutocomplete`, `MuiAutocomplete`, `MuiSelect`.
A library `Select` block is excluded by the presence of `<SelectTrigger>`, which
every library Select has and no MUI Select does.

## Totals

| | mounts |
|---|---|
| Converted — Formik pivots (`SelectFieldFds` / `ComboboxField`) | 158 |
| Converted — direct library composition (`Select` / `Combobox`) | 112 |
| **Converted total** | **270** |
| **Remaining on MUI** | **22** |
| **Total selection fields** | **292** |

## The 22 remaining, every one with a reason

### Not a site — the two legacy adapters themselves (2)

They must outlive their consumers, so they are not convertible work.

| file | consumers left |
|---|---|
| `components/AutocompleteField.tsx` | 2 — `StixCoreObjectsField`, `LocationField` (both ornament batch) |
| `components/fields/SelectField.tsx` | 4 — `AuthorizedMembersField` + list item (#44), `StixCoreObjectFilesAndHistory`, `JsonMapperRepresentationAttributeForm` |

`AutocompleteFreeSoloField` was a third adapter. It is converted, so it no longer
appears here: it composes the library directly and its four consumers went with
it.

### Parked with a recorded reason (20 mounts)

The last two rows are consumers of the `SelectField` adapter, not MUI mounts of
their own: their mount is already counted once at the adapter file above. They
are listed here so the four adapter consumers each carry a visible reason.

| file | mounts | reason |
|---|---|---|
| `EntitySelectWithTypes` | 1 | ornament batch, FEEDBACK #47 → #155 |
| `FilterChipPopover` | 1 | ornament batch, FEEDBACK #47 → #155 |
| `StixCoreObjectContainer` | 1 | ornament batch, FEEDBACK #47 → #155 |
| `DashboardRelativeDateSelect` | 1 | FEEDBACK #43 — invisible state marker, Sandy designs at V2 |
| `CustomViewPreviewEntitySelector` | 1 | FEEDBACK #43 — same question |
| `ThemeForm` | 1 | FEEDBACK #45 — Select has no clear affordance |
| `ImportFilesList` | 1 | multi-value connector picker → Combobox wave |
| `ConnectorsStatusFilters` | 2 | EE-gated, unverifiable on this instance |
| `ListFilters` (add-filter) | 1 | reverted to MUI — see below |
| `WidgetCreationParameters` + `WidgetAttributesInput` | 10 | reverted to MUI — see below |
| `AuthorizedMembersField` + list item | 0 — via `SelectField` | FEEDBACK #44 — reverted, `dashboardRestriction` went intermittent |
| `StixCoreObjectFilesAndHistory` | 0 — via `SelectField` | its test drove MUI's hidden native select; asserts a flow a user cannot perform |

### Simply not done yet (0)

Empty. Every mount that was pending a decision has been converted.

2 adapters + 20 parked + 0 not done = the 22 remaining mounts.

#### The two e2e parkings, and what is actually known

`e2e group1` runs 15 tests. A failure there SKIPS the rest of the chain, so one
red test hides every test after it — which is why these surfaced one at a time
rather than together.

| SHA | passed | failed | skipped |
|---|---|---|---|
| `d9686dd4c1` | 3 | `_backgroundTask` — data entity search | 11 |
| `cc669e9f5c` (after the ListFilters revert) | 6 | `dashboard` — Dashboard CRUD | 8 |
| `ebb75fe246` | 6 | `dashboard` — Dashboard CRUD | 8 |

The first is FIXED, not re-diagnosed: "data entity search" passes from
`cc669e9f5c` on. Dashboard CRUD was **skipped** in the first run, never passing —
it only became visible once the first was cleared.

#### Why `ListFilters` is parked

Its conversion is the only change on this branch that `e2e group1` can be shown
to react to: `_backgroundTask.spec.ts` — "Verify background tasks pre-requisites
on data entity search" — fails at `getByRole('option', { name: 'Label' })` after
filling the add-filter field, with the panel closed and the typed text still in
the input. Reverted so 280 converted mounts are not held behind one site.

Root cause NOT established. Four candidate mechanisms were tested against the
converted component in jsdom and all four are ruled out — each renders the panel
open with the option present, which is the opposite of the CI state:

| candidate | result |
|---|---|
| a single `input` event (what Playwright's `fill` does) fails to open the panel | ruled out — panel opens, option present |
| a parent re-render (async data arriving) closes the panel | ruled out — panel stays open |
| options arriving after the text is typed are not listed | ruled out — option appears |
| blur closes the panel while the controlled text survives | ruled out — blur does not even close it |

So the mechanism needs the real page, not jsdom: it is not in the component's own
input/open/options wiring. Whoever picks this up should start from a running
platform on Data > Entities and watch the panel's `data-state` across the fill,
rather than re-testing the four above.

#### Why the widget Attribute cluster is parked

`dashboard` — Dashboard CRUD times out at
`getByTestId('widget-params-selection-0').getByRole('combobox', { name: 'Attribute' })`:
a name-based locator that never resolves. The failure snapshot shows a `generic`
carrying the text "Attribute" — an orphan MUI `InputLabel` naming nothing —
followed by a combobox with NO accessible name.

Root cause NOT established. The obvious explanation does not survive: the target
trigger already passes `aria-label={t_i18n('Attribute')}`, and `SelectTrigger`
only sets `aria-labelledby` when a `SelectLabel` exists, so the `aria-label`
should win. Reverted rather than guessed at.

#### The real finding underneath: 24 converted Selects have no `SelectLabel`

Sweeping the branch for library `Select` mounts with no `SelectLabel` found 24 —
13 with an orphan MUI `InputLabel` left above them, which renders as a `generic`
and names nothing, and 11 with no name at all. Independent of the e2e red, that
is a WCAG 4.1.2 defect introduced by this migration and it makes every one of
those fields unreachable by a name-based test.

The fix is the same everywhere and is NOT a workaround: the text in the orphan
`InputLabel` belongs in a `SelectLabel` inside the `Select`, which sets
`hasLabel` and wires the trigger's `aria-labelledby`. The MUI original expressed
the same association through `<Select label={...}>`. This is the next round's
work, and it should be done before any further conversion.

## Out of scope

`SearchField` — "Search these results" — belongs to the library and reaches the
products at a future bump. Not counted, not to be converted here. It is a
TextField in this tree today, so it does not appear in the numbers above.
