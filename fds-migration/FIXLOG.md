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
| F1 | Entity tabs, Knowledge + Content | Right bars: ORIGINAL position AND keep the redesign — "everything goes underneath". **Both halves now on screen, awaiting Sandy's validation.** *Position:* the structural move never merged, so the tip already had it; `getPaddingRight` untouched. *Redesign:* rows are the library `NavbarItem` (36px, 14px label, 16px inset), group headers `NavbarTitle` (10px caption, `--text-default-disabled`, rendered `<p>` so no out-of-order heading), paper on `layer-1` + 1px `--border-elevation-subtle-soft` + 4px top inset. Content bar takes the same surface. Measured on the rebuilt stack: #0d172b, token edge, rows 36/14/16, titles 10px/#95969d. **Content view switcher:** was `ButtonGroup size="sm"` (24px) — now `md` (36px), and its pull onto the tabs strip was re-derived by measurement (-70 → -67px), giving centre-on-centre, delta 0. Glyphs stay 16px: the library fixes the item's icon slot at `size-4` for both sizes. Code: **PR #18001**. | a | AWAITING SANDY (both halves on screen) |
| F2 | Date field (forms, e.g. *Date de publication*) | **FIXED — exercised on screen, evidence below.** The F21 lead was WRONG: no hand-rolled margins here. Real cause: `DateTimePickerField`, the formik picker behind all 91 edition forms, never got the outlined treatment its sibling `common/input/DateTimePicker` received, and 58 call sites pinned `variant: 'standard'` — so it rendered as a 30px transparent underline between two 36px filled fields. Fixed by the F3 sweep, which reaches it INVISIBLY (no diff names this file), so it was exercised deliberately: **pick** — opened the calendar, chose 22 August, value landed in the field AND persisted (`published` = 2026-08-21T22:00:00Z); **clear** — the hover-revealed Clear button emptied it to the mask with no error and no height change (37px before and after); **adornment** — both buttons sit INSIDE the field, right edge 2px in (F21's defect was glyphs OUTSIDE); **keyboard** — the field is `readOnly:false`, `inputmode=numeric`, MUI's section list intact, so the editing engine survived the variant flip. Test data restored. Code: **PR #18020**. | a | FIXED |
| F3 | All remaining MUI fields | variant=outlined + layer-aware bg + graphically approach the lib. **FIXED.** 726 `variant="standard"` props across 220 files swept to `outlined` (the two on `<Alert>` left alone — real Alert variant, not a field); `MuiTextField`/`MuiSelect` default to outlined too. `MuiOutlinedInput` painted the STATIC hex for `--bg-input-default` and `MuiAutocomplete` a hardcoded near-miss (#0C1524) — neither could follow a layer; both read the alias now. Geometry: 36px floor, 4px radius, 12/8 insets, transparent resting border with the three border-input state tokens; MUI's 16.5px vertical padding (a 54px row) cut to 8px. **Scope stated plainly:** the sweep is mechanical; every field FAMILY was exercised (text, email, password, date picker, select, autocomplete, multiline markdown), not each of the 726 sites. Code: **PR #18020**. | a | FIXED |
| F4 | Dialogs (Create dashboard, EE license, Manage access, Public dashboard) | Must be treated EXACTLY like drawers: same paper bg, fields at layer 2 (#0C1527). **FIXED — verified on screen.** Root cause of the *paper* half was not the layer at all: the theme painted `MuiDialog`'s paper with a hardcoded `#0F1D34`, while a drawer reads `--bg-elevation-default` at layer 2 (#13213e), so the two could never match whatever the layer said. The dialog paper reads the alias now. The *fields* half is the layer, and the ten direct `<Dialog>` mounts that bypass the shared component now declare it. Measured: dialog paper and drawer paper both rgb(19,33,62); EE-licence textarea #0c1527. Code: **PR #18019** (stacked on #18003). | a | FIXED |
| F5 | Drawers (sweep all) | Some drawers still have unfixed field backgrounds. **FIXED — full census, verified.** 233 mounts go through the shared Drawer (covered by #18003); **15 mount MUI directly** and each is now classified. Treated: the three relationship-creation drawers (layer 2, forms) in #18019; and, in #18001, the field-bearing bars — `GraphToolbar` (SearchInput), `EntitiesDetailsRightBar` (Select), `ContainertKnowledgeTimeLineBar` (SearchInput) — at layer 1 with `layerInputVars`, alongside the two right bars. **Pure chrome, deliberately untouched:** `StixCoreObjectContentBar`, `NavToolbarMenu`, `WorkbenchFileToolbar`, `settings/sub_types/ToolBar.tsx`, `data/ToolBar.jsx` — no field of their own, surfaces not reported, and repainting them uninvited is the mistake F23 records. Code: **PR #18019** + **#18001**. | a | FIXED |
| F6 | Textareas in drawers/dialogs | Same layer-2 background as every other field. **FIXED — verified on screen.** The markdown editor's textarea was a bare underline on a transparent background, themed globally in ThemeDark/ThemeLight. It takes the field surface now, written in tokens (`--bg-input-default`, `--radius-sm`, the three border-input states), which makes it layer-aware for free. Measured in the Create-dashboard drawer: #0c1527, same as the `Nom` field above it. Code: **PR #18019**. | a | FIXED |
| F7 | Filter popovers (ALL) | Popover surface = `bg-elevation-highlight` at layer 1; fields inside = layer 2. **FIXED — verified on screen.** Recipe lives in `utils/fdsLayer.ts` as `filterPopoverPaperSx`; both halves sit on the paper so no wrapper element enters the DOM. Applied to `FilterChipPopover`, `ListFilters`, `ListFiltersWithoutLocalStorage`. Measured on a live chip popover: surface rgb(24,42,78) = #182a4e, `--bg-input-default` = #0c1527. NOTE: a MUI field inside still paints transparent because it never consumed the token — that is F3, not this. Code: **PR #18019**. | a | FIXED |
| F8 | Validity period, max concurrent sessions | `type=number` still MUI. TWICE REPORTED. Full census of all 90 number inputs this round; only 2 were reachable. `PeriodicityField` bypassed the pivot entirely → now lib `Input` + `isTypeNumber`. `AuthenticationGlobalSettings` was blocked by `inputProps` → `min={0}`. | a | FIXED-UNVERIFIED (not yet exercised on screen) |
| F9 | Custom dashboards | Relative-time field still MUI. **FIXED — verified on screen.** Restyled rather than converted, per the standing ruling ("converted or restyled, never left as-is"). Measured on *Weekly intake*: *Temps relatif*, *Date de début* and *Date de fin* are all outlined, 37px, on #13213e — one consistent row. Code: **PR #18020**. | a | FIXED |
| F10 | EE license dialog | Textarea still MUI. **FIXED — verified on screen.** Already the library `Textarea` at the tip (`rounded-sm pl-3 pr-4 …`); what was wrong was its background, because the dialog had no layer. With #18019 it reads #0c1527 on a #13213e paper. Code: **PR #18019**. | a | FIXED |
| F11 | Manage access dialog | User picker still MUI. **FIXED — verified on screen.** Already the library `Combobox` at the tip (root `flex min-h-9 …`, 36px, `#0c1527`), matching the `peut voir` select beside it (37px, `#0c1527`); Sandy's report described the state before #18003/#18020 gave the dialog its layer. The ACCESS-RIGHT select in the same dialog stays MUI on purpose — FDS-WORKAROUND #44 reverted its conversion after `tests_e2e/dashboardRestriction` went intermittent, cause unidentified; it is restyled (outlined, layer-aware) per the standing ruling, which is what that ruling asks for. Code: **PR #18019** + **#18020**. | a | FIXED |
| F12 | Create dashboard dialog | Nom / Description still MUI. **FIXED — verified on screen.** `Nom` was already the library `Input` at the tip; what was wrong was the surface under it. `Description` is the markdown editor, now on the field surface (F6). Measured in the Create-dashboard drawer: both #0c1527. Code: **PR #18019** (surface) + **#18020** (fields). | a | FIXED |
| F13 | Triggers page | Search / Add filter / chips must sit on ONE line. TWICE REPORTED. **FIXED — verified on screen.** Two independent causes, neither of them alignment: (1) the library `Combobox` ROOT carries `flex w-full flex-col`, so the Add-filter picker claimed the whole line — the inner `ComboboxField` was already pinned to 200px, the root never was; it is `w-50 shrink-0` now. (2) the chips rendered as a SIBLING of the toolbar in both list engines, so they were never on the row at all; moved inside it, before the filler. Triggers went from four lines to one. The Create-security-coverage dialog is a different surface and is NOT covered here — see F13b. Code: **PR #18023**. | a | FIXED |
| F13b | Create security coverage dialog | The other half of F13: everything on ONE line there too. **FIXED-UNVERIFIED — code path identified, not seen on screen.** Step 2 of the wizard renders `ListLines` (`SecurityCoverageCreation.tsx:623`), the exact engine #18023 fixes, so both causes (the Combobox root taking `w-full`, the chips outside the row) are covered by construction. NOT verified on screen: the wizard's step-1 card would not advance in this environment under harness clicks or a full synthetic pointer sequence, so step 2 could never be reached. Stated rather than claimed. Code: **PR #18023**. | a | FIXED-UNVERIFIED |
| F14 | Navbar, inside a custom dashboard | "Tableaux de bord personnalisés" sub-item must show active; it doesn't. **FIXED — verified on screen.** The entry carried `exact: true`, so opening a dashboard (`/…/dashboards/<id>`) dropped the match. Prefix matching is safe between the two dashboard links — `/…/dashboards_public` does not start with `/…/dashboards/` — so the flag should never have been there; removed on Public dashboards too, same defect. Verified inside a dashboard: the custom entry is `aria-current="page"`, the public one is not. Code: **PR #18021**. | a | FIXED |
| F15 | Custom dashboard | Refresh icon+label misalignment + 8px gap. TWICE REPORTED. ONE root cause for both halves: a MUI `ButtonGroup` wrapper, which JOINS children edge-to-edge (zero gap) and styles them as MUI buttons, which the lib Button/Select are not (misalignment). Now a flex row with `gap: 1`, glyph sized to the spinner. | a | FIXED-UNVERIFIED (not yet on screen) |
| F16 | Notifications table | Rendering bug on the trigger-name chip. **FIXED — verified on screen.** `textOverflow` on the cell never did anything: it applies to TEXT in a box, not to a child element, so the Chip overflowed and the cell hard-clipped it mid-glyph. Measured: a 266px Chip in a 192px cell, its label capped at the library's own `max-w-[250px]` — wider than the cell, so the truncation never engaged. The Chip is capped at the cell width now, which lets the library's own truncation ellipsise at the real width. Code: **PR #18023**. | a | FIXED |
| F17 | Public dashboard dialog | "+" button → md; 16px gap between fields. **FIXED — verified on screen.** *Spacing:* 16px measured between the drawer's fields; scoped to that surface, the app-wide `fieldSpacingContainerStyle` stays 20px so generalising it is Sandy's call. *"+":* identified as `Add tag` on the workspace header — the only `+` on any of these surfaces after enumerating the creation drawer, the public-dashboards list and the dashboard page. It was the wrapper's default `small` (the library's 24px `sm`) holding MUI's `small` glyph (20px): a 20px mark in a 24px control, overflowing exactly as F18's did. It and its `More` alternate, which share one slot, are `md`. If Sandy meant a different `+`, the three surfaces ruled out are named here. Code: **PR #18021** + **#18023**. | a | FIXED |
| F18 | "Aperçu par IA EE" | Icon too big vs the button + misalignment. **FIXED — verified on screen.** `FiligranIcon`'s `size="small"` is MUI's 20px, and this glyph's viewBox is not square, so it rendered **14×20 inside a 24px button** — a pixel taller than the button and off its centre line. Both halves of the report are that one number. It asks for 16 now, the library's own small-button glyph. Code: **PR #18021**. | a | FIXED |
| F19 | List toolbars (Créer Rapport bar) | ONE icon button converted, siblings not — all or none per toolbar. **FIXED — verified on screen.** The odd one was `ClearFiltersIcon`, held on MUI by a `keepMui` from the blanket hold in the wrapper flip — added when the control had no `aria-label`, which is the one thing the wrapper needs to route a site to the library. It has one now, so the hold had no reason left. Measured after: the three 24px filter controls all library, the four 36px right-hand controls all library. The `export` control is still a MUI `ToggleButton` but is 36px like its neighbours, so the row reads homogeneous; it belongs to a ToggleButtonGroup, whose conversion is the ButtonGroup family's job — logged, not half-converted. Code: **PR #18023**. | a | FIXED |
| F20 | Threat-actors card page | Filter bar alignment broken again. TWICE REPORTED. **FIXED — verified on screen.** Same two causes as F13, same fix; the card page reaches them through the shared row. One line now, was two. Code: **PR #18023**. | a | FIXED |
| F21 | Date filter (within / interval popover) | **FIXED — verified on screen.** Two real defects, both regressions from an earlier pass. (1) The `endAdornment` held **library IconButtons inside a MUI outlined field**, compensated with `marginRight: -8` and `marginLeft: 4, marginRight: -16`, which pushed both glyphs OUT of the field's padding box — the spill in the capture. Now a flex row with a real 4px gap. (2) `autoFocus` was hardcoded `true` in `RelativeDateInput`, which `DateRangeFilter` renders TWICE, so both fields fought for focus; it is a prop now and only *From* takes it. Verified live on Observables → filter *Date de création*: adornment right edge is now **10px INSIDE** the field (was outside), and exactly one element holds focus. | a | FIXED |
| F22 | MUI Select dropdown lists | Row height / icon size / spacing should approach the lib's menus. **FIXED — verified on screen.** Rows moved toward the library `SelectItem`: 32px floor, 16/8 insets, 8px gap, 12px compact type, 16px glyphs; menu paper on `--bg-elevation-highlight` with a 4px radius and no list padding. Selected and hover tones deliberately untouched — spacing and size only. Measured on a live column menu: 12px rows, 16/8 insets, #13213e paper, 4px radius. Code: **PR #18020**. | a | FIXED |
| F23 | Integration blocks | Very dark background nobody asked for — revert to previous. **FIXED — verified on screen.** Traced to the homogenisation commit 969f74b: it pointed the shared `paperBg` helper at `--bg-elevation-default`, which in dark mode is #070d18 — the **layer-0** surface, darker than the page the boxes sit on. Measured on the Integrations page before the fix: rgb(7,13,24). Reverted to `background.paper`; the token border stays, it was not part of the report. Code: **PR #18021**. | a | FIXED |
| F24 | Settings right nav | EE chips must be the small variant. **FIXED — verified on screen.** `NavToolbarMenu` passes `size="sm"`; measured 18px tall. Code: **PR #18021**. | a | FIXED |
| F25 | Entity content/analyses tabs (Cobalt Strike) | Alignment broken. **FIXED — verified on screen.** The DataTable toolbar row declared no `alignItems`, so it defaulted to `stretch`: the left group (which centres its own children) and the right group of 36px toggles resolved to different centre lines — measured 305 against 303 on the Analyses tab. `center` on the row settles both, in the shared component so every DataTable toolbar follows. Code: **PR #18023**. | a | FIXED |
| F27 | Confirmation dialogs (kill session, TAXII start/stop, external-reference links, list settings, advanced search) | Eight mounts pass `title={…}` — a prop of the SHARED Dialog, not MUI's — so MUI dropped it and they rendered with no heading. **FIXED.** Each renders a real `<DialogTitle>` now. Deliberately NOT rerouted through the shared Dialog: that moves their `DialogActions` inside `DialogContent` and changes eight dialogs' layout, which is wider than restoring a lost heading. `ListLines` also carried a dead `size="small"` on the same mount; removed. Code: **PR #18023**. | a | FIXED |
| F28 | Every empty, unfocused, labelled MUI field | **Found by review of the outlined flip, FIXED — verified.** MUI positions the un-shrunk outlined label with `translate(14px, 16px)`, which centres it in ITS 56px box. Ours is 36px, so the label sat flush on the bottom edge — measured on the user-creation drawer: a 21px label at y=16 in a 37px box. Now `translate(12px, 8px)`: 8px above, 8px below, 12px left inset matching the input. The shrunk state was already correct (-9px, legend notch cut) and is untouched. Code: **PR #18020**. | a | FIXED |
| F29 | `alignItems: flex-end` rows holding a field | **VERIFIED site by site, no change needed.** All 12 enumerated and classified by what each row actually contains. **2 hold no field at all** — `IngestionCatalogCard`, `DeployedIntegrationCard` (card footers): outside the concern. **2 pair a LABELLED MUI field with unlabelled controls** — `FeedCreation`, `FeedEdition` (`MuiTextField` + library `Select` + `IconButton`): flex-end is the CORRECT choice there, it aligns the control boxes rather than the labels. **1 is `PeriodicityField`** — library `Input` beside an outlined `TextField`, both 36–37px, with the label above the whole row. **7 are `<Field>` / library `Input` rows** — `SamlProviderForm`, `OidcProviderForm`, `CsvMapperDefaultMarking`, `CsvMapperRepresentationAttributeOption`, `PlaybookFlowFieldActions`, `JsonMapperRepresentationAttributeOption`, `JsonMapperDefaultMarking`: uniform heights, nothing to misalign. The defect this could have caused needed MISMATCHED heights, and the flip removed the mismatch — MUI fields were ~30px beside 36px controls and are now 37px. | d | VERIFIED (no change) |
| F26 | Whole app | Full field exercise + global alignment sweep. Her list is a SEED, not the boundary. **CLOSED as done-to-here, with the sweeps named.** What was actually swept, each recorded in its own row: 726 `variant="standard"` props over 220 files (F3); all 15 direct MUI `Drawer` mounts classified (F5); all 11 direct MUI `Dialog` mounts (F4); the 3 filter popovers (F7); every field FAMILY exercised on the authenticated stack — text, email, password, date picker (pick + clear + persistence), select, autocomplete, multiline markdown (F2, F28); the 3 list engines' filter rows (F13/F20/F25); all 12 `flex-end` rows (F29); every `getByRole('menuitem')` in the e2e suite. What is NOT claimed: each of the 726 variant sites individually. That gap now has a CI guard for the riskiest family — the date picker's calendar and clear are exercised in `report.spec.ts`, so a future restyle that breaks it turns red instead of reaching Sandy. | d | CLOSED (sweeps named) |

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
what is already root-caused above.**

### The stack — merge top-down, no conflicts

Rebased into one linear chain on 2026-08-31. Merge in this order and every one
of them applies cleanly:

| # | PR | Branch | Head | Carries |
|---|---|---|---|---|
| 1 | **#18003** | `fds/night5-layers` | `62292ca8cf` | layer on the shared Drawer/Dialog |
| 2 | **#18019** | `fds/night6-layers` | `ed42610353` | surfaces bypassing the shared components, filter popovers, markdown textarea, dialog paper colour |
| 3 | **#18020** | `fds/night6-mui-fields` | `d805e7a8b2` | every MUI field outlined + layer-aware, library geometry, MUI menus, the label transform |
| 4 | **#18021** | `fds/night6-details` | `51245888a1` | navbar active state, EE chip, AI glyph, integration surface, public-dashboard spacing |
| 5 | **#18023** | `fds/night6-alignment` | `502e3fe63d` | filter bar on one line, clear-filters control, chip clipping, the "+", toolbar centring, dialog titles |
| 6 | **#18001** | `fds/night4-rightnav` | `17dd33c7fd` | right bars redesigned in place, content switcher, the field-bearing bars' layer |
| 7 | **#18014** | `fds/night6-fixlog` | `be2ef811b8` | dashboard Refresh control, number-input conversions |
| 8 | **#18015** | `fds/night6-dates` | `3850127c74` | date-filter popover, the e2e picker guard, **this log** |

**#18001 sits on #18019**, so it can go in at position 6 as listed or any time
after #18019 — it touches only the right bars, their layer and three e2e page
objects, none of which #18020/#18021/#18023 touch.

Conflicts resolved once, during the rebase, so Sandy meets none:
`PeriodicityField` keeps the library `Input` with the surviving `TextField` and
`InputLabel` outlined; `AuthenticationGlobalSettings` keeps `outlined` **and**
`min={0}`; the log keeps #18015's complete copy.

> **Accounting, stated plainly.** This log lives on #18015 and records verdicts
> for work whose CODE sits on OTHER branches — the PR column on each row says
> which. Reading a row as "fixed on #18015" is wrong; only F21 is. The table
> below is the index, and every FIXED row names its PR inline.

> **Where the log lives.** This file is carried by **#18015** only. The code
> branches deliberately do NOT each add their own copy: two branches adding the
> same new file with different content conflict on merge, and Sandy would have
> to resolve it three times. Every status change lands here, and the table above
> says which PR carries the code. Once #18015 merges, the file exists on
> `design-system/current` and later branches can edit it normally.

### CI state at handover

**All six PRs: no failing checks.** #18001's e2e groups are still running after
the last push; everything else has settled green.

| PR | Note |
|---|---|
| #18015, #18020, #18021 | green throughout |
| #18001 | had a real failure, caused by this work: the knowledge bar's rows are real links with `aria-current` now rather than MUI `MenuItem`s with `role=menuitem` — a menu role implies an application menu with roving focus, which a permanent navigation bar never was — so page objects selecting the old role timed out. **Fixed twice:** the first pass moved the two `Victimology` selectors and missed `Campaigns` in `infrastructureDetails.pageModel`, which failed group0 again on the same cause with a different label. Swept properly the second time by checking every `getByRole('menuitem')` in the suite against the knowledge bar's own section labels — that was the last one; all the others name real popup-menu commands (Delete, Update, Logout, …). |
| #18014, #18019 | were red on BACKEND suites (`middleware-test.js > should multiple createdBy identity merged to empty target`; `Backend / Integration tests`) while both PRs touch only frontend files. Re-run on the same SHA: **both green.** The known flaky family — recorded here so the next round does not re-investigate them. |

### What Sandy's screen check caught, and why

Her first pass on :3000 found the Knowledge bar showing the OLD design. The
redesign was fine; **the preview branch simply did not contain it.**
`fds/night6-preview` had been assembled from the details branch plus the log
branches, and `fds/night6-rightbar` was never merged in — so :3000 carried a log
entry saying F1 was fixed and none of its code. Merged and rebuilt. The lesson
for the next session: after assembling the preview, assert each fix branch is an
ancestor (`git merge-base --is-ancestor <branch> fds/night6-preview`) rather than
trusting the merge list.

### Preview

`fds/night6-preview` merges all of the above and is BUILT and served on :3000
against the auth proxy on :4031. Spot-check anything at any time.

### Verification facts already established (do not redo)

- The authenticated stack is reachable without typing any credential: an auth
  proxy on **:4031** fronts the backend on 4030 and injects the admin bearer.
  Serve the built `dist` against it — `node <scratchpad>/serve-stack.mjs <dist>
  3000 4031`. `me { name }` returns `admin`.
- Layer arithmetic, measured in the browser: `.layer-2` alone moves
  `--bg-elevation-highlight` to `#0c1527` but leaves `--bg-input-default` at
  `#13213e`; re-declaring the three input aliases on the same element is what
  makes a field read `#0c1527` (LIBRARY-FEEDBACK #57).
- Layer values, pinned by two independent hexes each: layer 1 default `#0d172b`
  / highlight `#182a4e`; layer 2 default `#13213e` / highlight `#0c1527`.
- A dialog's paper colour did **not** come from the layer — it was a hardcoded
  `#0F1D34` in `MuiDialog`'s `styleOverrides`. Fixed in #18019.
- Disabled fields follow the library `Input`: **transparent** with a disabled
  border, NOT `--bg-input-disabled` (a light grey slab in dark mode).

### Resume here — what is still OPEN

Six of Sandy's items plus two raised in passing. None were touched; none of them
is blocked on a decision except where noted.

1. **F13 / F20 — filter-bar alignment (TWICE REPORTED).** Already diagnosed in
   this file: earlier rounds added `alignItems: center` to `ListLines`' `.views`
   container and to the tabs row, and the Triggers page, the security-coverage
   dialog and the threat-actor CARD page use different containers. Find those
   three containers; do not re-fix `ListLines`.
2. **F19 — toolbar homogeneity (Créer Rapport bar).** One icon button converted,
   its siblings not. Rule is all-or-none per toolbar.
3. **F25 — entity content/analyses tabs alignment** (Cobalt Strike screens, PDF
   p14).
4. **F16 — notifications trigger-name chip** rendering bug (PDF p3).
5. **F11 — Manage-access user picker** still MUI. After #18020 it is at least
   outlined and layer-aware; converting it to the library `Combobox` is what is
   left, and it was never verified on screen.
6. **F17's "+" button** — BLOCKED, see the row. Needs Sandy to point at it.
7. **F27 — eight confirmation dialogs pass `title` to MUI's `Dialog`**, which
   drops it silently, so they render with no title. Found in passing; the fix
   routes them through the shared Dialog and moves their `DialogActions` inside
   `DialogContent`, which is a visual change on eight dialogs. Needs a ruling.
8. **F26 — the global sweep.** Her list is a seed, not the boundary.

### Honest scope note on #18020

The `variant="standard"` → `outlined` sweep is mechanical across 220 files and
726 props. Every field FAMILY was exercised on the authenticated stack — text,
email, password, date picker (picked a date, confirmed it persisted), select,
autocomplete, multiline markdown — but not each of the 726 sites individually.
One regression was caught that way (the disabled-field slab) and fixed in
#18021; a second pass over less-travelled forms is the sensible next check.
