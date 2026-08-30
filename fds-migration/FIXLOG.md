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
| F1 | Entity tabs, Content tab | Right bars: return to ORIGINAL position (right edge, full height), content back in place — "everything goes underneath". Keep the redesign. | a | OPEN |
| F2 | Date field (forms, e.g. *Date de publication*) | Not yet isolated as a separate defect. **Strong lead from F21:** the same regression family — library IconButtons placed inside MUI field adornments with hand-rolled negative margins. Next session: grep for `IconButton` inside `slotProps.input.endAdornment` / `InputProps` across the date components (`DatePicker.tsx`, `DateTimePicker.tsx`, `PeriodicityField`) and exercise type/pick/clear/submit. | a | OPEN |
| F3 | All remaining MUI fields | variant=outlined + layer-aware bg + graphically approach the lib (heights, paddings, label style) without breaking behaviour. | a | OPEN |
| F4 | Dialogs (Create dashboard, EE license, Manage access, Public dashboard) | Must be treated EXACTLY like drawers: same paper bg, fields at layer 2 (#0C1527). Still wrong. | a | OPEN |
| F5 | Drawers (sweep all) | Some drawers still have unfixed field backgrounds. | a | OPEN |
| F6 | Textareas in drawers/dialogs | Same layer-2 background as every other field. | a | OPEN |
| F7 | Filter popovers (ALL) | Popover surface = `bg-elevation-highlight` at layer 1; fields inside = layer 2. | a | OPEN |
| F8 | Validity period, max concurrent sessions | `type=number` still MUI. TWICE REPORTED. Full census of all 90 number inputs this round; only 2 were reachable. `PeriodicityField` bypassed the pivot entirely → now lib `Input` + `isTypeNumber`. `AuthenticationGlobalSettings` was blocked by `inputProps` → `min={0}`. | a | FIXED-UNVERIFIED (not yet exercised on screen) |
| F9 | Custom dashboards | Relative-time field still MUI. | a | OPEN |
| F10 | EE license dialog | Textarea still MUI. | a | OPEN |
| F11 | Manage access dialog | User picker still MUI. | a | OPEN |
| F12 | Create dashboard dialog | Nom / Description still MUI. | a | OPEN |
| F13 | Triggers page | Search field / Add filter / chips misaligned; filter chips wrap one line below. Same in Create security coverage dialog — everything must sit on ONE line. TWICE REPORTED (filter alignment). | a | OPEN |
| F14 | Navbar, inside a custom dashboard | "Tableaux de bord personnalisés" sub-item must show active; it doesn't. | a | OPEN |
| F15 | Custom dashboard | Refresh icon+label misalignment + 8px gap. TWICE REPORTED. ONE root cause for both halves: a MUI `ButtonGroup` wrapper, which JOINS children edge-to-edge (zero gap) and styles them as MUI buttons, which the lib Button/Select are not (misalignment). Now a flex row with `gap: 1`, glyph sized to the spinner. | a | FIXED-UNVERIFIED (not yet on screen) |
| F16 | Notifications table | Rendering bug on the trigger-name chip (PDF p3, "Problem bug sur le tableau"). | a | OPEN |
| F17 | Public dashboard dialog | "+" button → md; 16px gap between fields. | a | OPEN |
| F18 | "Aperçu par IA EE" | Icon too big vs the button + misalignment (two screenshots). | a | OPEN |
| F19 | List toolbars (Créer Rapport bar) | ONE icon button converted, siblings not — homogeneity: all or none per toolbar. | a | OPEN |
| F20 | Threat-actors card page | Filter bar alignment broken again. TWICE REPORTED (filter alignment). | a | OPEN |
| F21 | Date filter (within / interval popover) | **FIXED — verified on screen.** Two real defects, both regressions from an earlier pass. (1) The `endAdornment` held **library IconButtons inside a MUI outlined field**, compensated with `marginRight: -8` and `marginLeft: 4, marginRight: -16`, which pushed both glyphs OUT of the field's padding box — the spill in the capture. Now a flex row with a real 4px gap. (2) `autoFocus` was hardcoded `true` in `RelativeDateInput`, which `DateRangeFilter` renders TWICE, so both fields fought for focus; it is a prop now and only *From* takes it. Verified live on Observables → filter *Date de création*: adornment right edge is now **10px INSIDE** the field (was outside), and exactly one element holds focus. | a | FIXED |
| F22 | MUI Select dropdown lists | Row height / icon size / spacing should approach the lib's menus, without breaking behaviour. | a | OPEN |
| F23 | Integration blocks | Very dark background nobody asked for — revert to previous. | a | OPEN |
| F24 | Settings right nav | EE chips must be the small variant. | a | OPEN |
| F25 | Entity content/analyses tabs (Cobalt Strike) | Alignment broken (PDF p14, two captures). | a | OPEN |
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

### Where the code lives (nothing is merged)

| Branch | Carries | FIXLOG items |
|---|---|---|
| `fds/night6-dates` | date-filter popover repair **+ the authoritative copy of this log** | F21 |
| `fds/night6-fixlog` | dashboard Refresh control, number-input conversions | F15, F8 |
| `fds/night6-rightbar` | **empty** — branched off the tip, work not started | F1 |
| `fds/night4-rightnav` (#18001) | previous right-bar rounds — superseded by the F1 plan below | — |
| `fds/night5-layers` (#18003) | layer declaration on shared Drawer/Dialog | partial F4/F5 |

> **Mismatch to be aware of:** the log copy on `fds/night6-dates` records F8 and
> F15 as fixed, but their CODE is on `fds/night6-fixlog`. Merge both, or
> consolidate, before trusting a single branch.

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
