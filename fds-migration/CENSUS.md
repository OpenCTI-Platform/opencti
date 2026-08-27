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
| Converted — direct library composition (`Select` / `Combobox`) | 107 |
| **Converted total** | **265** |
| **Remaining on MUI** | **27** |
| **Total selection fields** | **292** |

## The 27 remaining, every one with a reason

### Not a site — the two legacy adapters themselves (2)

They must outlive their consumers, so they are not convertible work.

| file | consumers left |
|---|---|
| `components/AutocompleteField.tsx` | 2 — `StixCoreObjectsField`, `LocationField` (both ornament batch) |
| `components/fields/SelectField.tsx` | 4 — `AuthorizedMembersField` + list item (#44), `StixCoreObjectFilesAndHistory`, `JsonMapperRepresentationAttributeForm` |

### Parked with a recorded reason (8)

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

### Simply not done yet (17)

Surfaced by this census and never counted before. No blocker known for any of
them; all are aliased-import Autocompletes or the default+named `Select` form.

| file | mounts |
|---|---|
| `CsvMapperConditionalEntityMapping` | 2 |
| `CsvMapperRepresentationAttributeRefForm` | 2 |
| `CsvMapperRepresentationForm` | 1 |
| `CsvMapperRepresentationAttributeForm` | 1 |
| `JsonMapperRepresentationForm` | 1 |
| `JsonMapperRepresentationAttributeRefForm` | 1 |
| `CustomFieldCreation` | 1 |
| `CustomFieldEdition` | 1 |
| `ConfidenceOverrideField` | 1 |
| `FilterAutocomplete` | 1 |
| `AutocompleteFreeSoloField` | 1 |
| `SecurityCoverageAttackPatterns` | 1 |
| `StixDomainObjectAttackPatternsKillChain` | 1 |
| `StixDomainObjectThreatKnowledge` | 1 |
| `AuthorizedMembersField` + list item, `StixCoreObjectFilesAndHistory`, `JsonMapperRepresentationAttributeForm` | via `SelectField` adapter |

## Out of scope

`SearchField` — "Search these results" — belongs to the library and reaches the
products at a future bump. Not counted, not to be converted here. It is a
TextField in this tree today, so it does not appear in the numbers above.
