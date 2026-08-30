# FIXLOG — Sandy's visual-pass findings

One line per finding. An item leaves this log ONLY as **FIXED** (with how it was
verified on screen) or **BLOCKED** (with a reason Sandy can rule on). Nothing
exits by omission. The next session reads this file before starting.

Statuses: `OPEN` · `FIXED` · `BLOCKED` · `NOT-REPRO`
Classes: **(a)** regression → fix · **(b)** fixed-at-tip → name the PR ·
**(c)** environment/backend → document · **(d)** accepted backlog → name it

> **SOURCE GAP:** the annotated PDF "Retours finale2" was referenced as attached
> but is not on this machine (only `retour-env-3000.pdf`, the FIRST pass, is in
> ~/Downloads). Entries below are numbered from the brief's text. Items whose
> meaning depends on a screenshot caption are marked `NEEDS-SCREENSHOT` — they
> are actionable only once the PDF is available, and are NOT silently dropped.

| # | Screen | What's wrong | Class | Status |
|---|---|---|---|---|
| F1 | Entity tabs, Content tab | Right bars: return to ORIGINAL position (right edge, full height), content back in place — "everything goes underneath". Keep the redesign. | a | OPEN |
| F2 | Date field (everywhere) | ALREADY BROKEN — regression from a previous pass. Fix FIRST, then use it as the check: type / pick / clear / submit after every restyle. | a | OPEN |
| F3 | All remaining MUI fields | variant=outlined + layer-aware bg + graphically approach the lib (heights, paddings, label style) without breaking behaviour. | a | OPEN |
| F4 | Dialogs (Create dashboard, EE license, Manage access, Public dashboard) | Must be treated EXACTLY like drawers: same paper bg, fields at layer 2 (#0C1527). Still wrong. | a | OPEN |
| F5 | Drawers (sweep all) | Some drawers still have unfixed field backgrounds. | a | OPEN |
| F6 | Textareas in drawers/dialogs | Same layer-2 background as every other field. | a | OPEN |
| F7 | Filter popovers (ALL) | Popover surface = `bg-elevation-highlight` at layer 1; fields inside = layer 2. | a | OPEN |
| F8 | Coverage validity period, others | `type=number` still MUI — the lib `isTypeNumber` exists. TWICE REPORTED. | a | OPEN |
| F9 | Custom dashboards | Relative-time field still MUI. | a | OPEN |
| F10 | EE license dialog | Textarea still MUI. | a | OPEN |
| F11 | Manage access dialog | User picker still MUI. | a | OPEN |
| F12 | Create dashboard dialog | Nom / Description still MUI. | a | OPEN |
| F13 | Triggers page | Search field / Add filter / chips misaligned; filter chips wrap one line below. Same in Create security coverage dialog — everything must sit on ONE line. TWICE REPORTED (filter alignment). | a | OPEN |
| F14 | Navbar, inside a custom dashboard | "Tableaux de bord personnalisés" sub-item must show active; it doesn't. | a | OPEN |
| F15 | Custom dashboard | Refresh button icon+label misalignment — REPORTED IN A PREVIOUS ROUND AND STILL THERE. Plus 8px gap between Refresh and the 5min select. TWICE REPORTED. | a | OPEN |
| F16 | Notifications table | Rendering bug on the trigger-name chip (overflow / covered). | a | OPEN · NEEDS-SCREENSHOT |
| F17 | Public dashboard dialog | "+" button → md; 16px gap between fields. | a | OPEN |
| F18 | "Aperçu par IA EE" | Icon too big vs the button + misalignment (two screenshots). | a | OPEN |
| F19 | List toolbars (Créer Rapport bar) | ONE icon button converted, siblings not — homogeneity: all or none per toolbar. | a | OPEN |
| F20 | Threat-actors card page | Filter bar alignment broken again. TWICE REPORTED (filter alignment). | a | OPEN |
| F21 | Date filter (within / interval popover) | COMPLETELY BROKEN — urgent; likely the same regression family as F2. | a | OPEN |
| F22 | MUI Select dropdown lists | Row height / icon size / spacing should approach the lib's menus, without breaking behaviour. | a | OPEN |
| F23 | Integration blocks | Very dark background nobody asked for — revert to previous. | a | OPEN |
| F24 | Settings right nav | EE chips must be the small variant. | a | OPEN |
| F25 | Entity content/analyses tabs (Cobalt Strike) | Alignment broken. | a | OPEN · NEEDS-SCREENSHOT |
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
  was not among them, so it was never in scope. The census was of one blocking
  pattern, not of every remaining number field.
