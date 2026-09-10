# CENSUS-FINAL — every control family in the OpenCTI front

Machine pass, one script, one run. Regenerate:

```bash
node fds-migration/scripts/census-all-families.mjs opencti-platform/opencti-front/src
```

Measured on `fds/consumption-night` (base `design-system/current` @ `075f23a`
— after #17977, #17978 and #17980 merged — library pin `1f7c64c`). This is the closing document for the component phase:
it states, for every family and every remaining MUI site, **why** it is still
on MUI. There is no "not looked at yet" bucket — see *The uncensused bucket* at
the end, which the script itself proves empty and fails on if it is not.

## Method, and the two things that broke the first pass

Same resolution as `census-selection-fields.mjs`: the **local name** of every
imported symbol is resolved per file, then usages of that local name are
counted. Matching on the element name is what missed two earlier counts —
aliases (`MuiSwitch`, `MUIAutocomplete`, `MuiSelect`) are invisible to it.

Two corrections this script needed that the selection-field one did not:

1. **`component={X}` is a mount.** Formik's field adapters are never written as
   JSX elements. Counting only `<X` reported 1 SwitchField site instead of 108
   and 0 TextField pivot sites instead of 620. Both forms are counted now.
2. **Type-only imports are not mounts.** `<SelectProps` matches the element
   regex inside `Omit<SelectProps<string>, …>`. Nine symbols
   (`SelectProps`, `PopoverProps`, `GridTypeMap`, `ButtonProps`, …) carried
   mount counts for things that are never mounted. Symbols ending in `Props` or
   `TypeMap`, and every `import type { … }`, are excluded.

A converted site counts as its own mount; a site on a **legacy MUI adapter**
counts once at the adapter file. Parking a site therefore lowers both numerator
and denominator, exactly as `CENSUS.md` established.

## Totals

| family | total | on lib | on MUI |
|---|---:|---:|---:|
| Input | 648 | 634 (14 direct + 620 pivot) | 14 |
| Textarea | 34 | 31 (5 direct + 26 pivot) | 3 |
| Checkbox | 72 | 63 (61 direct + 2 pivot) | 9 |
| Radio | 14 | 11 | 3 |
| Switch | 195 | 109 (1 direct + 108 pivot) | 86 |
| Select | 186 | 184 (83 direct + 101 pivot) | 2 |
| Combobox | 109 | 105 (48 direct + 57 pivot) | 4 |
| SearchField | 2 | 2 | 0 |
| Button | 5 | 4 | 1 |
| IconButton | 95 | 84 | 11 |
| Chip | 78 | 70 | 8 |
| Fab | 14 | 0 | 14 |
| ToggleButton | 116 | 1 | 115 |
| Slider | 9 | 5 | 4 |
| **TOTAL** | **1577** | **1303 (82.6 %)** | **274** |

**Two families carry 73 % of everything left**: ToggleButton (115) and Switch
(86). Every other family together is 73 sites.

## Reason codes

| code | meaning |
|---|---|
| `lib-gap#N` | the library has no equivalent, or its equivalent lacks a capability this site needs. `N` is the `LIBRARY-FEEDBACK.md` entry where one exists |
| `arbitration-pending` | blocked on a design or product decision that is Sandy's, not a migration's |
| `parked-e2e` | converted once, reverted on a deterministic E2E red whose cause is still not established |
| `legacy-adapter` | a MUI Formik adapter that must outlive its remaining consumers |
| `frontier` | convertible, no library gap, no pending arbitration — but its own wave, for a reason stated per family |
| `unnamed` | would need an accessible name invented rather than read |
| `dead-code` | unreachable |

## Per family

### Input — 14 on MUI

| sites | code | why |
|---|---|---|
| `TextField.tsx:181` | `frontier` | the pivot's own MUI fallback. It renders when a site is out of the Input contract (`multiline`, `select`, a leading interactive adornment, `onBeforePaste`, a non-string label, an unplaceable prop). It is the pivot working as designed, not a missed site |
| `AutocompleteField.tsx:125` | `legacy-adapter` | the `renderInput` of the legacy MUI Autocomplete adapter; dies with its adapter |
| `PeriodicityField.tsx:99,108` | `frontier` | two number fields inside a composite unit picker |
| `FormSchemaEditor.tsx` ×8 | `frontier` | the form-schema builder, a screen of its own — see the Switch note below, the same file holds 31 switches |
| `IntegrationsAvailable.tsx:210`, `IntegrationsDeployed.tsx:152` | `frontier` | search inputs inside the integrations list |

### Textarea — 3 on MUI

`BulkTextModal.tsx:85`, `WorkflowTransitions.tsx:287`,
`FormSchemaEditor.tsx:1744` — all `frontier`. The 24 multiline sites the night
brief expected were already converted: the `TextareaField` pivot carries **26**
`component={TextareaField}` mounts plus 5 direct `<Textarea>`, and #17946
landed the last of them. These three are raw `<TextField multiline>` outside
the pivot.

### Checkbox — 9 on MUI

| sites | code | why |
|---|---|---|
| `FilterChipPopover.tsx:400` | `parked-e2e` | **do not touch.** `CENSUS.md` records this exact checkbox as the suspect in the parked `locator.check: Clicking the checkbox did not change its state` red |
| `StixCoreObjectContainer.tsx:252`, `FormFieldRenderer.tsx:226`, `TriggerEditionOverview.tsx:378`, `GroupEditionMarkings.tsx:256`, `WidgetCreationParameters.tsx:285`, `HiddenTypesField.tsx:185` | `frontier` | each sits inside a `FormControlLabel`. The wrapper must be unwrapped onto the library Checkbox's own `label`, and the clone-injection trap has to be read per site — it is what broke a consent checkbox in #17946 |
| `ListLines.jsx:468`, `DataTableToolBar.jsx:3392` | `frontier` | select-all checkboxes in the two list shells; `edge="start"` and `disableRipple` are MUI box-model props with no library counterpart, so the row geometry has to be re-read |

### Radio — 3 on MUI

`StixCoreObjectAskAI.tsx:324,344` and `DataTableToolBar.jsx:3106` — `frontier`.
All three are inside `FormControlLabel`, same unwrap as the Checkbox block.

### Switch — 86 on MUI, the second-largest block

Measured, not estimated: **77 of the 86 sit inside a `FormControlLabel`**, and
they are spread over 31 files with a long tail — `FormSchemaEditor.tsx` alone
holds 31, `TransitionForm.tsx` 6, and 20 files hold exactly one.

`frontier`, and it is a wave of its own for three reasons stated together:

1. **The clone-injection trap is live here.** `FormControlLabel` copies
   `checked`/`name`/`onChange` onto its control child *only when the child does
   not define them*. Which side owns the handler has to be read per site; the
   gates cannot see a handler that silently stops firing. This is the failure
   #17946 hit.
2. **Row height changes 38px → 20px on every one of them.** MUI's Switch is a
   58×38 box (34×14 track in a 12px padding box); the library's is `h-5 w-9`.
   Sandy accepted that change for the 107 pivot rows in #17976, so the geometry
   is settled — but it lands on ~30 more forms here.
3. **The compensations have to come off with it.** The 9 sites outside a
   `FormControlLabel` are not therefore free: `Experience.tsx` wraps its two
   switches in `Box sx={{ marginBlock: -0.75 }}`, a −6px pull that exists only
   to cancel MUI's padding box and would misalign the row once that box is gone.

A partial pass is worse than none: it leaves 20px and 38px switch rows side by
side on the same screens.

### Select — 2 on MUI

| site | code | why |
|---|---|---|
| `DashboardRelativeDateSelect.tsx:53` | `arbitration-pending` — `lib-gap#43` | the field marks "this filter is constraining the view". Sandy withdrew the original library ask on 2026-08-26 after failing to notice the current 1px marker on the live site; the **form** of a perceptible marker is hers to design at V2 |
| `SelectField.tsx:104` | `legacy-adapter` | 4 consumers left |

`ThemeForm.tsx` left this list in this change set: `clearable` (library #190)
retired FDS-WORKAROUND #45.

### Combobox — 4 on MUI

| site | code | why |
|---|---|---|
| `FilterChipPopover.tsx:327`, `ListFilters.tsx:197` | `parked-e2e` | both converted, both reverted on deterministic reds; `CENSUS.md` carries one test-side lead for the first and none for the second. Neither is a library defect as far as anything measured shows |
| `CustomViewPreviewEntitySelector.tsx:112` | `arbitration-pending` — `lib-gap#43` | same withdrawn ask as `DashboardRelativeDateSelect` |
| `AutocompleteField.tsx:152` | `legacy-adapter` | 2 consumers left |

### Button — 1, IconButton — 11, Chip — 8

**Re-measured after #17977 and #17978 merged, and the earlier reading was
wrong.** An earlier pass tagged three of these `in-flight PR` because those two
pull requests touch the files. They touch them without converting these mounts:
the MUI site set in these three families is **byte-identical before and after
both merges** — only line numbers moved. What the waves added is 4 library
mounts (Button 2 → 4, IconButton 82 → 84), not a single MUI removal here.
`in-flight PR` is therefore no longer a code in this document.

`Button.tsx:226` is `frontier` **by design, not by omission**: it is the
wrapper's deliberate MUI fallback, and its own comment says so — *"These retire
when the library grows the missing axis"*, the axis being the tone gap recorded
as LIBRARY-FEEDBACK #53. `StixCoreObjectsSuggestions.jsx:340` and
`DataTableToolBar.jsx` are ordinary `frontier` sites the naming wave did not
reach.

The other 9 IconButton and 8 Chip sites are `frontier`: `TopBanner`,
`GraphToolbarItem`, `NewsFeedToastManager` ×2, `CertStrategyForm`,
`SSOSingletonStrategies` ×3, `ThreatActorIndividualBiographics`,
`ResponseDialog`; and `FilterIconButtonContainer`, `PublicFeedLines`,
`PublicStreamLines`, `PublicTaxiiLines`, `FormFieldRenderer`,
`IngestionCatalogUseCaseChip`, `PlaceholderNode`, `DataTableToolBar`.

### Fab — 14 on MUI

`lib-gap` — **the library ships no Fab.** Verified by bytes: there is no `fab`
directory under the installed
`dist/components`, and no `Fab` export in `index.d.ts`. These 14 are the
"create" buttons at the bottom-right of the list screens. Nothing to convert
onto; this is a component request, not a migration task.

### ToggleButton — 115 on MUI, the largest block

`frontier`, with a caveat that makes it a design question before it is a
migration one. The library's nearest equivalent is `ButtonGroup` /
`ButtonGroupItem`, and `ButtonGroupItem` is **icon-only by contract**:
`{ value, icon, "aria-label" }`, no text child. The 115 sites are not one
population:

- true segmented controls (`ViewSwitchingButtons`, `ListLines`, `ListCards`,
  `ExportButtons`, `ContainerHeader`, …) — these map onto `ButtonGroup`;
- **standalone** `ToggleButton`s used as kebab/menu triggers
  (`PopoverMenu.tsx:35`, every `*Popover.tsx`, `WorkspaceKebabMenu`) — a group
  of one is not a group; these are `IconButton`s wearing a toggle;
- toggles carrying **text**, which `ButtonGroupItem` cannot render.

Splitting those three is the first step of that wave, not something to decide
inside a closing PR.

### Slider — 4 on MUI

`frontier`. `InputSliderField.tsx:112,166`, `SliderField.tsx:58`,
`StixCoreObjectOpinionsRadarDialog.tsx:196`. No gap: Radix's Slider root gives
`onValueCommit`, the equivalent of MUI's `onChangeCommitted` these sites use.
The work is per-site — value shape (`number` vs `number[]`) and the `sx` track
styling each have to be re-read.

## The uncensused bucket

**Empty, and the script fails if it is not.** 98 distinct MUI symbols are
mounted in the front. 13 are the control families above (274 mounts). The
other 85 are each assigned to a named bucket; an unassigned symbol makes
`census-all-families.mjs` exit 1.

| bucket | symbols | mounts |
|---|---:|---:|
| in a censused control family | 13 | 274 |
| `no-lib-equivalent` — container / layout | 18 | 2079 |
| `lib-exists` — not this wave | 25 | 2007 |
| `no-lib-equivalent` — list / table / data display | 29 | 1984 |
| `no-lib-equivalent` — feedback | 3 | 208 |
| form scaffolding — follows its control, never converted alone | 7 | 182 |
| `no-lib-equivalent` — speed dial | 3 | 8 |
| **uncensused** | **0** | **0** |

`lib-exists — not this wave` is the honest headline for what comes after the
controls: 2007 mounts of `Typography` (519), `Tooltip` (496), `MenuItem` (284),
`DialogActions` (200), `Tab` (128) and 20 more, all with a library component
already built. The control phase is 82.6 % done; the surface phase has not
started.

## One finding outside the count

`migration-state.json`'s `libComponentUsage` declares **Paper only** — 12
entries, all Paper. The Select, Combobox, Checkbox, Switch and Input waves each
adopted a library component without declaring it, so `check-fds-conformity.mjs`
is not watching any of them: none would be caught reverting to MUI. This change
set declares its own three adoptions and leaves the backfill as a separate,
mechanical task.
