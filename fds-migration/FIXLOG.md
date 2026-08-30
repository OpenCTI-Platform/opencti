# FIXLOG — Sandy's visual-pass findings

One line per finding. An item leaves this log ONLY as **FIXED** (with how it was
verified on screen) or **BLOCKED** (with a reason Sandy can rule on). Nothing
exits by omission. The next session reads this file before starting.

Statuses: `OPEN` · `FIXED` · `BLOCKED` · `NOT-REPRO`
Classes: **(a)** regression → fix · **(b)** fixed-at-tip → name the PR ·
**(c)** environment/backend → document · **(d)** accepted backlog → name it

> **SOURCE:** `retour-opencti-fds-2.pdf` (18 pages), supplied mid-round and read.
> Its captions are reconciled with the brief, so the `NEEDS-SCREENSHOT` marks are
> lifted.

| # | Screen | What's wrong | Class | Status |
|---|---|---|---|---|
| F1 | Entity tabs, Knowledge + Content | Right bars: return to ORIGINAL position (right edge, full height), content back in place — "everything goes underneath". Keep the redesign. **FIXED — verified on screen.** The structural move never merged, so the tip already had the original placement; only the INSIDE of the bars changed. Knowledge bar rows are now the library `NavbarItem` (36px, 14px label, 16px inset), group headers `NavbarTitle` (10px caption, `--text-default-disabled`, rendered `<p>` so no out-of-order heading), paper on `layer-1` + 1px `--border-elevation-subtle-soft` + 4px top inset. Content bar takes the same surface and edge. Measured at 1600x900: paper #0d172b at x=1400 h=900, highlight resolves #182a4e inside the bar, rows 36/14/16, headers 28/10/#95969d. Code: **PR #18001** (branch force-pushed, its old below-the-tabs move is gone). | a | FIXED |
| F2 | Date field (forms, e.g. *Date de publication*) | **FIXED — verified and exercised on screen.** The F21 lead was WRONG: there are no hand-rolled negative margins here. Real cause: `DateTimePickerField`, the formik picker behind all 91 edition forms, never got the outlined treatment its sibling `common/input/DateTimePicker` received, and 58 of its call sites pass `variant: 'standard'` explicitly — so it rendered as a 30px transparent underline between two 36px filled fields, calendar glyph hanging off the end. Fixed by the F3 sweep. Exercised: opened the picker, picked 15 August, value landed in the field AND persisted (`published` = 2026-08-14T22:00:00Z); test data restored. Code: **PR #18020**. | a | FIXED |
| F3 | All remaining MUI fields | variant=outlined + layer-aware bg + graphically approach the lib. **FIXED.** 726 `variant="standard"` props across 220 files swept to `outlined` (the two on `<Alert>` left alone — real Alert variant, not a field); `MuiTextField`/`MuiSelect` default to outlined too. `MuiOutlinedInput` painted the STATIC hex for `--bg-input-default` and `MuiAutocomplete` a hardcoded near-miss (#0C1524) — neither could follow a layer; both read the alias now. Geometry: 36px floor, 4px radius, 12/8 insets, transparent resting border with the three border-input state tokens; MUI's 16.5px vertical padding (a 54px row) cut to 8px. **Scope stated plainly:** the sweep is mechanical; every field FAMILY was exercised (text, email, password, date picker, select, autocomplete, multiline markdown), not each of the 726 sites. Code: **PR #18020**. | a | FIXED |
| F4 | Dialogs (Create dashboard, EE license, Manage access, Public dashboard) | Must be treated EXACTLY like drawers: same paper bg, fields at layer 2 (#0C1527). **FIXED — verified on screen.** Root cause of the *paper* half was not the layer at all: the theme painted `MuiDialog`'s paper with a hardcoded `#0F1D34`, while a drawer reads `--bg-elevation-default` at layer 2 (#13213e), so the two could never match whatever the layer said. The dialog paper reads the alias now. The *fields* half is the layer, and the ten direct `<Dialog>` mounts that bypass the shared component now declare it. Measured: dialog paper and drawer paper both rgb(19,33,62); EE-licence textarea #0c1527. Code: **PR #18019** (stacked on #18003). | a | FIXED |
| F5 | Drawers (sweep all) | Some drawers still have unfixed field backgrounds. **FIXED — verified on screen.** Census: 233 mounts go through the shared Drawer (covered by #18003); 15 mount MUI directly. Of those, the three relationship-creation drawers carry forms and had no layer — they declare it now. The rest are toolbars and the tab-scoped right bars, which are layer 1 by design, not layer 2. Code: **PR #18019**. | a | FIXED |
| F6 | Textareas in drawers/dialogs | Same layer-2 background as every other field. **FIXED — verified on screen.** The markdown editor's textarea was a bare underline on a transparent background, themed globally in ThemeDark/ThemeLight. It takes the field surface now, written in tokens (`--bg-input-default`, `--radius-sm`, the three border-input states), which makes it layer-aware for free. Measured in the Create-dashboard drawer: #0c1527, same as the `Nom` field above it. Code: **PR #18019**. | a | FIXED |
| F7 | Filter popovers (ALL) | Popover surface = `bg-elevation-highlight` at layer 1; fields inside = layer 2. **FIXED — verified on screen.** Recipe lives in `utils/fdsLayer.ts` as `filterPopoverPaperSx`; both halves sit on the paper so no wrapper element enters the DOM. Applied to `FilterChipPopover`, `ListFilters`, `ListFiltersWithoutLocalStorage`. Measured on a live chip popover: surface rgb(24,42,78) = #182a4e, `--bg-input-default` = #0c1527. NOTE: a MUI field inside still paints transparent because it never consumed the token — that is F3, not this. Code: **PR #18019**. | a | FIXED |
| F8 | Validity period, max concurrent sessions | `type=number` still MUI. TWICE REPORTED. Full census of all 90 number inputs this round; only 2 were reachable. `PeriodicityField` bypassed the pivot entirely → now lib `Input` + `isTypeNumber`. `AuthenticationGlobalSettings` was blocked by `inputProps` → `min={0}`. | a | FIXED-UNVERIFIED (not yet exercised on screen) |
| F9 | Custom dashboards | Relative-time field still MUI. **FIXED — verified on screen.** Restyled rather than converted, per the standing ruling ("converted or restyled, never left as-is"). Measured on *Weekly intake*: *Temps relatif*, *Date de début* and *Date de fin* are all outlined, 37px, on #13213e — one consistent row. Code: **PR #18020**. | a | FIXED |
| F10 | EE license dialog | Textarea still MUI. **FIXED — verified on screen.** Already the library `Textarea` at the tip (`rounded-sm pl-3 pr-4 …`); what was wrong was its background, because the dialog had no layer. With #18019 it reads #0c1527 on a #13213e paper. Code: **PR #18019**. | a | FIXED |
| F11 | Manage access dialog | User picker still MUI. | a | OPEN |
| F12 | Create dashboard dialog | Nom / Description still MUI. **FIXED — verified on screen.** `Nom` was already the library `Input` at the tip; what was wrong was the surface under it. `Description` is the markdown editor, now on the field surface (F6). Measured in the Create-dashboard drawer: both #0c1527. Code: **PR #18019** (surface) + **#18020** (fields). | a | FIXED |
| F13 | Triggers page | Search field / Add filter / chips misaligned; filter chips wrap one line below. Same in Create security coverage dialog — everything must sit on ONE line. TWICE REPORTED (filter alignment). | a | OPEN |
| F14 | Navbar, inside a custom dashboard | "Tableaux de bord personnalisés" sub-item must show active; it doesn't. | a | OPEN |
| F15 | Custom dashboard | Refresh icon+label misalignment + 8px gap. TWICE REPORTED. ONE root cause for both halves: a MUI `ButtonGroup` wrapper, which JOINS children edge-to-edge (zero gap) and styles them as MUI buttons, which the lib Button/Select are not (misalignment). Now a flex row with `gap: 1`, glyph sized to the spinner. | a | FIXED-UNVERIFIED (not yet on screen) |
| F16 | Notifications table | Rendering bug on the trigger-name chip (PDF p3, "Problem bug sur le tableau"). | a | OPEN |
| F17 | Public dashboard dialog | "+" button → md; 16px gap between fields. | a | OPEN |
| F18 | "Aperçu par IA EE" | Icon too big vs the button + misalignment (two screenshots). | a | OPEN |
| F19 | List toolbars (Créer Rapport bar) | ONE icon button converted, siblings not — homogeneity: all or none per toolbar. | a | OPEN |
| F20 | Threat-actors card page | Filter bar alignment broken again. TWICE REPORTED (filter alignment). | a | OPEN |
| F21 | Date filter (within / interval popover) | **FIXED — verified on screen.** Two real defects, both regressions from an earlier pass. (1) The `endAdornment` held **library IconButtons inside a MUI outlined field**, compensated with `marginRight: -8` and `marginLeft: 4, marginRight: -16`, which pushed both glyphs OUT of the field's padding box — the spill in the capture. Now a flex row with a real 4px gap. (2) `autoFocus` was hardcoded `true` in `RelativeDateInput`, which `DateRangeFilter` renders TWICE, so both fields fought for focus; it is a prop now and only *From* takes it. Verified live on Observables → filter *Date de création*: adornment right edge is now **10px INSIDE** the field (was outside), and exactly one element holds focus. | a | FIXED |
| F22 | MUI Select dropdown lists | Row height / icon size / spacing should approach the lib's menus. **FIXED — verified on screen.** Rows moved toward the library `SelectItem`: 32px floor, 16/8 insets, 8px gap, 12px compact type, 16px glyphs; menu paper on `--bg-elevation-highlight` with a 4px radius and no list padding. Selected and hover tones deliberately untouched — spacing and size only. Measured on a live column menu: 12px rows, 16/8 insets, #13213e paper, 4px radius. Code: **PR #18020**. | a | FIXED |
| F23 | Integration blocks | Very dark background nobody asked for — revert to previous. | a | OPEN |
| F24 | Settings right nav | EE chips must be the small variant. | a | OPEN |
| F25 | Entity content/analyses tabs (Cobalt Strike) | Alignment broken (PDF p14, two captures). | a | OPEN |
| F27 | Confirmation dialogs (kill session, TAXII start/stop, external-reference links, list settings, advanced search) | **Found in passing, not on Sandy's list.** Eight mounts import MUI's `Dialog` but pass `title={…}` — a prop of the SHARED Dialog, not MUI's. MUI drops it silently, so these dialogs render with NO title. Fixing it means routing them through the shared Dialog, which also wraps their `DialogActions` inside `DialogContent` — a visual change on eight dialogs that is wider than a background fix. Left for Sandy to rule on rather than bundled into a layer PR. | a | OPEN — needs a ruling |
| F26 | Whole app | Full field exercise + global alignment sweep. Her list is a SEED, not the boundary. | a | OPEN |

## Why the twice-reported items survived the last round

- **F15 (Refresh alignment)** — never opened. Previous rounds fixed alignment in
  `ListLines`' filter row and in `StixDomainObjectTabsBox`; the custom-dashboard
  Refresh control is neither, and I never looked at it. It was not a fix that
  failed, it was a fix never attempted.
- **F13 / F20 (filter alignment)** — the previous fix added `alignItems: center`
  to `ListLines`' `.views` container and to the tabs row. Those are two specific
  containers; the Triggers page and the threat-actor CARD page use different
  ones, so the fix could not reach them. Same defect class, different DOM.
- **F8 (number fields)** — the previous round converted the six fields blocked
  only by `slotProps`, and reported exactly that. The coverage validity period
  was not among them, so it was never in scope. The census covered ONE blocking
  pattern, not every number field. Redone properly this round: all 90
  `type="number"` inputs enumerated and each classified as pivoting /
  MUI-fallback / raw. That is the census that should have been run first.

---

## HANDOVER — state at end of session

**This file is the handover. Read it before starting; do not re-investigate
what is already root-caused below.**

### Where the code lives — open PRs, none merged

| PR | Branch | Carries | FIXLOG items |
|---|---|---|---|
| **#18015** | `fds/night6-dates` | date-filter popover repair **+ this log, the authoritative copy** | F21 |
| **#18014** | `fds/night6-fixlog` | dashboard Refresh control, number-input conversions | F15, F8 |
| **#18001** | `fds/night4-rightnav` | right-bar redesign, original placement kept (branch force-pushed — its old below-the-tabs move is gone) | F1 |
| **#18003** | `fds/night5-layers` | layer declaration on the shared Drawer/Dialog | partial F4/F5 |
| **#18019** | `fds/night6-layers` | the surfaces that bypass the shared components, filter popovers, markdown textarea, dialog paper colour — **stacked on #18003** | F4, F5, F6, F7, F10 |
| **#18020** | `fds/night6-mui-fields` | every remaining MUI field outlined + layer-aware, library geometry, MUI menus — **stacked on #18019** | F2, F3, F9, F12, F22 |

> **Where the log lives.** This file is carried by **#18015** only. The code
> branches deliberately do NOT each add their own copy: two branches adding the
> same new file with different content conflict on merge, and Sandy would have
> to resolve it three times. So every status change lands here, and the table
> above says which PR carries the code. Once #18015 merges, the file exists on
> `design-system/current` and later branches can edit it normally.

### Resume here

**F1 (right bars) is the cheapest large win and the approach is settled:** the
tip still contains the ORIGINAL bars and Roots, because #18001 never merged. So
branch from the tip and apply ONLY the internal redesign — 36px rows, 14px type,
caption group headers, layer-1 surface (`--bg-elevation-default-layer-1`,
`#0d172b`), left border (`--border-elevation-subtle-soft`), 4px slot inset. Do
NOT re-do any structural move: the bars stay fixed, right-attached, full height,
and `getPaddingRight` stays exactly as the tip has it. `fds/night6-rightbar` is
already branched off the tip for this and is otherwise untouched.

**Then F2**, using the lead recorded in its row (same regression family as F21).

**Then BATCH 2 (F4–F7)**, for which the mechanism is fully established in
`utils/fdsLayer.ts` and LIBRARY-FEEDBACK #57: put `fdsLayerClass(2)` **and**
`layerInputVars` on the SAME node as the surface. For filter popovers the rule
differs: the popover surface is `--bg-elevation-highlight` at **layer 1**, the
fields inside at **layer 2**.

### Verification facts already established (do not redo)

- The authenticated stack is reachable without typing any credential: an auth
  proxy on **:4031** fronts the backend on 4030 and injects the admin bearer.
  Serve the built `dist` against it — `node <scratchpad>/serve-stack.mjs <dist>
  3000 4031`. `me { name }` returns `admin`.
- Layer arithmetic, measured in the browser: `.layer-2` alone moves
  `--bg-elevation-highlight` to `#0c1527` but leaves `--bg-input-default` at
  `#13213e`; re-declaring the three input aliases on the same element is what
  makes a field read `#0c1527`.
