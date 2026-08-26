# Selection fields: screen → field → verdict

Every selection surface in `opencti-front`, with a verdict on each line. Counts
are regenerated from the tree, not carried by hand:

```bash
# converted
grep -rl "component={ComboboxField}"  opencti-platform/opencti-front/src --include='*.tsx' --include='*.jsx' | wc -l
grep -rl "component={SelectFieldFds}" opencti-platform/opencti-front/src --include='*.tsx' --include='*.jsx' | wc -l
# still MUI (each must appear in the table below with a reason)
grep -rn "<Autocomplete[^A-Za-z]" opencti-platform/opencti-front/src --include='*.tsx' --include='*.jsx'
# and the census that MUST cover BOTH import forms -- see the correction below
cd opencti-platform/opencti-front && for f in $(grep -rl "<Select" src --include='*.jsx' --include='*.tsx'); do \
  perl -0777 -ne 'exit(1) unless (/import\s*\{[^}]*\bSelect\b[^}]*\}\s*from\s*.\@mui\/material./s
    or /import\s+Select\s+from\s*.\@mui\/material\/Select./s)' "$f" \
  && echo "$(perl -0777 -ne 'my $c=()=/<Select(?![A-Za-z])/g; print $c' "$f") $f"; done | sort -rn
```

## CORRECTION — the raw `<Select>` wave is NOT closed

An earlier version of this table said it was. That was wrong, and the error was
in the census, not in the conversions: the command only matched the **named**
import form

    import { Select } from '@mui/material';

and missed the **default** form

    import Select from '@mui/material/Select';

which 13 files use. **39 MUI `<Select>` mounts were never counted.** They were
found by opening the mass-edit drawer of the bulk toolbar during a pointer proof
and seeing two `MuiSelect-select` triggers where the census claimed none: the
DOM contradicted the count, and the DOM was right.

| Screen | File | Mounts | Verdict |
|---|---|---|---|
| Widgets → parameters | `WidgetCreationParameters.tsx` | 9 | **NOT DONE** — never censused |
| Data → Feeds (edit) | `FeedEdition.jsx` | 8 | **NOT DONE** — never censused |
| Data → Feeds (create) | `FeedCreation.tsx` | 8 | **NOT DONE** — never censused |
| Home dashboard settings | `HomeDashboardSettings.jsx` | 3 | **NOT DONE** — never censused |
| Settings → SSO | `SecretFieldControl.tsx` | 2 | **NOT DONE** — never censused |
| Data → bulk toolbar | `DataTableToolBar.jsx` | 2 | **NOT DONE** — action type + attribute pickers; its 18 Autocompletes ARE converted |
| Widgets | `WidgetAttributesInput.tsx` | 1 | **NOT DONE** — never censused |
| Entity header | `StixDomainObjectHeader.jsx` | 1 | **NOT DONE** — never censused |
| Workbench | `WorkbenchFileContent.jsx` | 1 | **NOT DONE** — never censused |
| List views | `ListLines.jsx`, `ListCards.jsx` | 2 | **NOT DONE** — never censused |
| Settings → Themes | `ThemeForm.tsx` | 1 | **MUI, FEEDBACK #45** (already on this table) |
| Import files | `ImportFilesList.tsx` | 1 | **MUI, Combobox wave** (already on this table) |

Two of the 39 were already accounted for. **37 are newly surfaced work.** The
lesson is the same one this migration keeps relearning and is worth stating once
more: a count produced by a pattern is only as good as the pattern's coverage of
the population, and the way to find out is to look at the rendered DOM.

## Totals

| Surface | On the library | Still MUI |
|---|---|---|
| Combobox — Formik pivot (`component={ComboboxField}`) | 44 files | 2 files (ornaments) |
| Combobox — direct composition | 9 files | 6 files |
| Select — Formik pivot (`component={SelectFieldFds}`) | 63 files | 0 |
| Select — direct composition | 17 files | 2 files |

The raw `<Select>` wave is **NOT closed** — see the correction above. The
*named-import* population is converted; the *default-import* population, 37
further mounts across 11 files, was never censused and is still to do.

## Still MUI — every line has a verdict

### Ornament batch — five sites, one cause

All five carry something in the field's input adornment. #155 closes this with
`startIcon` / `adornment` on `ComboboxField`; they move together on those
signatures, per Sandy's decision to defer them to the next round.

| Screen | Field | Ornament | Verdict |
|---|---|---|---|
| Entity forms (shared) | `LocationField` | search icon | **deferred → #155** |
| Entity forms (shared) | `StixCoreObjectsField` | search icon | **deferred → #155** |
| Bulk / entity pickers | `EntitySelectWithTypes` | type selector | **deferred → #155** |
| Entity container picker | `StixCoreObjectContainer` | create IconButton | **deferred → #155** (found this round, FEEDBACK #47) |
| Filters popover | `FilterChipPopover` value field | search-scope selector | **deferred → #155** (found this round, FEEDBACK #47) |

The batch was scoped at three coming into this round. Converting the raw
`<Autocomplete>` population found two more. Recorded rather than quietly folded
in, because the size of the next round changes with it.

### Blocked on a capability the library does not have

| Screen | Field | Verdict |
|---|---|---|
| Settings → Themes | `ThemeForm` login-aside type | **MUI, FEEDBACK #45** — the empty string is a real product state and Select has no clear part, while Combobox has `ComboboxClear`. Converting would mean losing the ability to empty the field, or inventing a "None" option — a product decision, not a migration's. |
| Import files | `ImportFilesList` connector picker | **MUI, Combobox wave** — multi-value. The census routing rule sends multi-value to `Combobox multiple`, not to `Select`, which is single-value by contract. The other two selects in that file are converted, hence the aliased import. |

### Blocked on a product/design question

| Screen | Field | Verdict |
|---|---|---|
| Settings → Custom views | `CustomViewPreviewEntitySelector` | **MUI, FEEDBACK #43** — view-constraining field. Sandy's verdict: the current 1px grey border is INVISIBLE to the eye, so a state marker the user cannot see does not do its job. Pattern to be designed at V2 (tint? icon? helper line? badge?). No library capability modelled on the invisible one. |
| Dashboards | `DashboardRelativeDateSelect` | **MUI, FEEDBACK #43** — second site of the same question. |

### Blocked on verification, not on capability

| Screen | Field | Verdict |
|---|---|---|
| Data → Connectors | `ConnectorsStatusFilters` (2 mounts) | **MUI** — EE-gated, so unverifiable on this instance. Not a reservation about the library: a conversion that cannot be exercised is not one to carry. |
| Entity → Data | `StixCoreObjectFilesAndHistory` | **MUI** — its test drove MUI's hidden native `<select>`, bypassing the visible option's `disabled` state, i.e. it asserted a flow a user cannot perform. Deferred rather than relax product logic or weaken the assertion. |
| Dashboards → access rights | `AuthorizedMembersField` + its list item | **MUI, FEEDBACK #44** — reverted. `dashboardRestriction` went intermittent after conversion and was reported as flaky, not passing. An access-rights control is not carried forward on the strength of a green re-run. |

### Not yet done — the remaining work, stated plainly

| Screen | Field | Verdict |
|---|---|---|
| Data → bulk toolbar | `DataTableToolBar` (18 mounts) | **NOT DONE** — its own pass. Uniform shape, but a class component whose handlers are `this.searchX.bind(this, i)` and `handleChangeActionInputValues.bind(this, i)`: the conversion changes those signatures from `(i, event, value)` to `(i, value, meta)`, so it is a handler refactor and not a prop rename. Same method as the FormSchemaEditor pass — a structural converter that BAILS per mount, with every diff read before it is written. |
| Saved filters | `SavedFiltersAutocomplete` | **NOT DONE** — carries `sx` theming on the outlined input (background, conditional border colour) and a `renderOption` passed in from its caller with the MUI props signature, so the caller moves with it. |

`src/components/AutocompleteField.tsx` — the legacy MUI adapter — stays until
the ornament batch lands, since the two deferred pivot mounts still use it. It is
not a site.
