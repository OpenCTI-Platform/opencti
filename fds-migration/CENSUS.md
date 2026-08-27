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
| Converted — direct library composition (`Select` / `Combobox`) | 123 |
| **Converted total** | **281** |
| **Remaining on MUI** | **11** |
| **Total selection fields** | **292** |

## The 11 remaining, every one with a reason

### Not a site — the two legacy adapters themselves (2)

They must outlive their consumers, so they are not convertible work.

| file | consumers left |
|---|---|
| `components/AutocompleteField.tsx` | 2 — `StixCoreObjectsField`, `LocationField` (both ornament batch) |
| `components/fields/SelectField.tsx` | 4 — `AuthorizedMembersField` + list item (#44), `StixCoreObjectFilesAndHistory`, `JsonMapperRepresentationAttributeForm` |

`AutocompleteFreeSoloField` was a third adapter. It is converted, so it no longer
appears here: it composes the library directly and its four consumers went with
it.

### Parked with a recorded reason (9 mounts)

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
| `AuthorizedMembersField` + list item | 0 — via `SelectField` | FEEDBACK #44 — reverted, `dashboardRestriction` went intermittent |
| `StixCoreObjectFilesAndHistory` | 0 — via `SelectField` | its test drove MUI's hidden native select; asserts a flow a user cannot perform |

### Simply not done yet (0)

Empty. Every mount that was pending a decision has been converted.

2 adapters + 9 parked + 0 not done = the 11 remaining mounts.

## Out of scope

`SearchField` — "Search these results" — belongs to the library and reaches the
products at a future bump. Not counted, not to be converted here. It is a
TextField in this tree today, so it does not appear in the numbers above.
