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
| Converted — Formik pivots (`SelectFieldFds` / `ComboboxField`) | 157 |
| Converted — direct library composition (`Select` / `Combobox`) | 112 |
| **Converted total** | **269** |
| **Remaining on MUI** | **22** |
| **Total selection fields** | **291** |

The denominator is DERIVED, not fixed. It was 292 while `CreatedByField` was
converted: its own `ComboboxField` mount counted as a pivot. Reverted, that site
consumes the `AutocompleteField` adapter, whose single mount the census counts
once at the adapter file — so the site stops being counted on its own and the
total drops to 291. Converting it again puts the mount, and the 292, back.

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
| `CreatedByField` (via `AutocompleteField`) | 0 — via the adapter | reverted to MUI — see below |
| `WidgetCreationParameters` + `WidgetAttributesInput` | 10 | reverted to MUI a second time — see below |
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


## Arbitration list — 2026-08-28

Each entry is something I did not decide alone. File, what it renders, the block
in one sentence, my recommendation.

| # | file | renders | blocked by | my recommendation |
|---|---|---|---|---|
| 1 | `private/components/common/lists/ListFilters.tsx` | the add-filter field | `_backgroundTask` "data entity search" timed out on it and four candidate mechanisms are ruled out in jsdom; cause needs a running platform | re-try the conversion and read the failure again before parking: the widget cluster failed the same way and turned out to be a SELECTOR defect, not a component one (see the note below) |
| 2 | `private/components/common/form/CreatedByField.jsx` | the Author picker | `report` "live entities creation" times out on the create row; the adapter is proven innocent by a jsdom probe (listbox named, row rendered inside it, text matches the page-model regex) | same: re-try and read the error, since the adapter is already exonerated in isolation |
| 3 | `components/fields/EntitySelectWithTypes.tsx`, `components/filters/FilterChipPopover.tsx`, `private/components/common/stix_core_objects/StixCoreObjectContainer.tsx` | pickers with an icon or button inside the input | the input-ornament gap, FEEDBACK #47 → library #155, which is NOT in the current pin `fc24f4b` | convert when #155 ships; nothing to do product-side |
| 4 | `components/dashboard/DashboardRelativeDateSelect.tsx`, `private/components/settings/sub_types/custom_views/CustomViewPreviewEntitySelector.tsx` | a field that tints itself while it constrains the view | FEEDBACK #43, no library equivalent, already deferred to V2 | V2, or a product convention (adornment or helper line) that needs no shell tint |
| 5 | `private/components/settings/themes/ThemeForm.tsx` | a Select the user must be able to empty | FEEDBACK #45 — the library Select has no clear affordance | V2 |
| 6 | `private/components/data/connectors/ConnectorsStatusFilters.tsx` | 2 EE-gated filters | cannot be reached on this instance, so no conversion can be verified | convert blind, or leave until an EE bench exists |
| 7 | `private/components/common/files/import_files/ImportFilesList.tsx` | the connector picker | it is a MULTIPLE MUI Select whose `renderValue` joins the names with commas; the library Select is single-value, so this is a Combobox conversion that replaces the comma list with chips | convert to a multiple Combobox and accept chips — it is the library standard everywhere else |
| 8 | `private/components/data/forms/view/FormFieldRenderer.tsx:468` | the attached-file chip | the chip carries `onDelete`; the library Chip has no delete affordance | ask the library for a removable chip; keep MUI here meanwhile |
| 9 | `private/components/data/DataTableToolBar.jsx:2896` | the "Search: <term>" chip | its `label` is JSX (`<strong>Search</strong>: term`); the library Chip's `label` is typed `string` | either split into two chips, or ask the library to accept a node |
| 10 | the `:3030` pilot | — | no CTI backend is running on this bench and standing up the full platform was ruled out for tonight | visit on another session's pilot |

### The lesson the widget cluster taught, worth applying to entries 1 and 2

`Dashboard CRUD` was blamed on the widget Select conversion for three rounds. The
A/B/A was clean — converted red, reverted green, re-converted red — and it was
still the wrong conclusion. The real error was a strict-mode violation:
`getByRole('combobox', { name: 'Attribute' })` matched TWO fields, because
`getByRole` matches the accessible name by SUBSTRING and the neighbouring field
is named "Date attribute".

That second name existed only because the accessible-name work gave that Select a
real label. So a correct fix surfaced a latent defect in a test selector, and the
conversion was never at fault. The fix went in the selector, never in the labels.

It took TWO fixes, and the first was not enough. With the selector disambiguated
the trigger resolved and was clicked, and the test then timed out one step later
on `getByRole('listbox', { name: 'Attribute' })` — the PANEL had no accessible
name either, because the converter emits a bare `<SelectContent>`. Both the
trigger and its listbox have to be named. The guard now checks both.

A red E2E on a converted field is not evidence that the conversion is wrong. Read
the error text before reverting: "resolved to 2 elements" and "element(s) not
found" are opposite diagnoses.


## The widget cluster, third and last attempt of the night

Converted, named, and reverted again. Each attempt moved `Dashboard CRUD` one
step further, which is the useful part of the record:

| attempt | where it stopped |
|---|---|
| converted, unnamed | `getByRole('combobox', { name: 'Attribute' })` — **0 matches** |
| + accessible names | same locator — **2 matches**, strict-mode violation, because the neighbour became "Date attribute" and `getByRole` matches by substring |
| + `exact: true` on the selector | past the trigger, then `getByRole('listbox', { name: 'Attribute' })` — the PANEL had no name |
| + `aria-label` on every `SelectContent` | past Attribute entirely, then `getByRole('combobox', { name: 'Relative time' })` |

The last one is not a naming defect. `DashboardWidgets.pageModel.ts:23` expects a
combobox named "Relative time" inside `widget-params-selection-0`, and no such
field exists there in either version — the labels in that container are "Sort by",
"Sort mode", a DYNAMIC one (`dataSelection[i].label` falling back to
"Date attribute"), and "Attribute" twice. The only "Relative time" in the product
is `DashboardRelativeDateSelect`, which is parked on MUI and lives elsewhere.

**The open question, for whoever takes this:** the test passes on the base branch,
so on MUI something does satisfy that locator inside that container. Establish
what, before touching the conversion again. The conversion has now been reverted
three times on evidence that turned out, twice, to be about something else.

Recommendation: reconvert, and fix `DashboardWidgets.pageModel.ts` rather than the
component — but only once someone has watched that container render on a running
platform. Do not revert a fourth time on a locator error alone.