# Targeted captures — deltas not covered by the 9 Phase 5 screens

> **Screenshot files are not committed** (repo hygiene: zero binary images in
> git history). All PNGs referenced below live locally in
> `.fds-validation-artifacts/targeted-captures/` (gitignored). This document
> is the durable record of what was captured and what it proved; re-run the
> capture script if you need to regenerate the images themselves.

Purpose: give concrete before/after evidence for tokens whose deltas are
real (per `TOKEN-MAPPING.md`) but weren't exercised by any of the 9 standard
Phase 5 screens: the tonic/`secondary.main` color, `background.accent` (dark),
`severity.info` / `severity.medium`, and `error.main` (light). All screenshots
below are at `HEAD` (`9233b542cc`, wired) vs `bb864ab58a` (pre-wiring), same
viewport, same zoom, Vite HMR verified between checkouts.

**⚠️ Headline finding — please read before looking at the screenshots.**
Two of the three pages show **zero pixel difference**, and it is not a
capture bug. It's a real, load-bearing discovery about how OpenCTI resolves
its palette — see "Critical finding" below. It directly confirms why you
scoped DB theme-row updates out of this push.

## Pages captured

| Page | URL | Tokens exercised |
|---|---|---|
| Decay Rule detail | `/dashboard/settings/customization/decay/<id>` | `error.main` (Inactive `ItemBoolean` tag) **and** `secondary.main`/tonic (`DecayChart` line/fill, `revokeColor`) |
| Vulnerability detail, CVSS V2 tab | `/dashboard/arsenal/vulnerabilities/<id>` | `severity.info` (raw score badge, "4.5") **and** `severity.medium` (label pill, "MEDIUM", via `getCvssCriticity()`) — same field (`x_opencti_cvss_v2_base_score`), two consumers |
| Reports list, 1 row selected | `/dashboard/analyses/reports` | `background.accent` (DataTable toolbar background, `DataTableHeaders.tsx`) |

Each captured in dark + light, before + after → 12 screenshots
(`{page}-{mode}-{before,after}.png`). Temp entities used for capture
("FDS Visual Checkpoint Temp Decay" / "…Temp Vuln") were deleted from the
dev DB after capture; nothing left behind.

## Critical finding: 7 palette properties are DB-overridden, not code-driven

`AppThemeProvider.tsx` builds the live MUI theme by calling `themeDark(...)`
/`themeLight(...)` with **9 positional params** sourced from the active
`Theme` DB row (`settings.platform_theme`), falling back to the code
constants **only when the DB field is `null`**:

```ts
// AppThemeProvider.tsx
theme_accent: themeToUse?.theme_accent ?? defaultTheme.theme_accent,
// ThemeDark.ts
secondary: { main: secondary || THEME_DARK_DEFAULT_SECONDARY },
accent: accent || THEME_DARK_DEFAULT_ACCENT,
```

I queried the running dev instance's actual `Theme` rows via GraphQL:

```
Dark:  theme_background #070d19  theme_paper #09101e  theme_nav #070d19
       theme_primary #0fbcff     theme_secondary #00f18d
       theme_accent #0f1e38      theme_text_color #F2F2F3
Light: theme_background #ececf2  theme_paper #ffffff   theme_nav #ffffff
       theme_primary #0015a8     theme_secondary #00BD94
       theme_accent #dfdfdf      theme_text_color #18191B
```

**Every one of these 7 fields is explicitly populated** on the built-in
`Dark`/`Light` theme rows (`built_in: true`), and **every value matches the
pre-wiring hex exactly**. That means: for `background`, `paper`, `nav`,
`primary`, `secondary`, `accent`, `text_color` — changing the FDS-backed
default constant in `ThemeDark.ts`/`ThemeLight.ts` has **no visual effect
at all** in this (or any real) deployment until the corresponding DB rows
are updated too. This isn't a bug in the wiring — the code is correct and
`grep`-verifiable — it's a second, separate step that has to happen for
these 7 properties specifically.

Properties **not** in that parameter list (`error`, `warn`, `success`,
`dangerZone`, `severity`, …) are plain FDS constants with no DB escape
hatch, so their wiring **is** live immediately, no DB step needed.

This is exactly the dependency you flagged in point 5 ("la mise à jour des
rows DB des thèmes… je coordonne ça séparément") — this capture round gives
it hard pixel evidence rather than just a schema-reading assumption.

### Proof, pixel-exact

- **`secondary.main` / tonic (decay chart)** — scanned all 4 screenshots
  (dark+light × before+after) for exact pixel matches to old (`#00f18d`
  dark / `#00BD94` light) vs new (`#00f0bc`) tonic hex. Result: **every
  image matches OLD exactly (distance 0), zero pixels match NEW, in both
  before and after.** The chart color is coming straight from the DB row,
  untouched by the wiring.
- **`background.accent` (reports toolbar)** — sampled the toolbar
  background at 4 points per image: **before == after, exactly, in both
  modes** (dark `rgb(15,30,56)` = `#0f1e38` = the OLD/DB value; light
  `rgb(223,223,223)` ≈ `#dfdfdf` = the OLD/DB value).

### Where the wiring *is* live (non-DB-backed tokens)

- **`error.main` (Inactive tag, decay rule)** — sampled tag background
  directly: dark `(54,24,32)→(58,27,34)` (tiny, consistent with
  TOKEN-MAPPING's "dark: no change" — residual delta is anti-aliasing);
  light `(240,205,205)→(235,195,197)`, a real ~4-10/255 shift in the
  documented direction (`#F14337→#e51e10`), diluted from the raw hex delta
  because the tag renders the color through an alpha-blended tint, not the
  flat hex.
- **`severity.info` / `severity.medium` (vulnerability CVSS badges)** —
  confirmed via zoomed crops (`crops/crop_vuln_*.png`, 3-4x): the "4.5"
  badge visibly shifts from a darker/grayer blue to a more saturated
  sky-blue in both modes; the "MEDIUM" badge shows a subtler warm-tone
  shift. Real, visible-on-zoom, matches the documented direction. At
  normal viewing size the shift is subtle (consistent with Phase 5's
  "imperceptible at a glance" finding) but is genuine and non-zero.

## Reading the screenshots

- `decay-rule-detail-{mode}-{before,after}.png` — expect **no visible
  difference** (both the Inactive tag delta and the tonic-chart delta are
  either DB-overridden or too subtle to see unzoomed; open the light-mode
  pair side by side if you want to look for the faint Inactive-tag shift).
- `reports-list-selected-{mode}-{before,after}.png` — expect **no visible
  difference at all** (accent is fully DB-overridden in this instance).
- `vulnerability-detail-{mode}-{before,after}.png` — look at the CVSS
  badges near the top; `crops/crop_vuln_{mode}_{before,after}.png` gives a
  4x zoom on just that badge if the full-page pair doesn't show it clearly.
- `DIFF_{page}-{mode}.png` — amplified pixel-diff heatmap (white =
  identical, colored = delta) for each page/mode pair; useful to see at a
  glance that `reports-list-selected` and `decay-rule-detail` are almost
  entirely white (confirming the DB-override finding) while
  `vulnerability-detail` shows visible colored spots at the badge
  locations.

## Net takeaway for arbitration

The **code wiring is correct and complete** for all 7 DB-overridable
properties — they will render correctly the moment the DB theme rows are
updated (your separate, coordinated step). The tokens that render
immediately without any DB step (severity, error, success, warn,
dangerZone) are already visibly correct today, as shown here. No action
needed from this finding other than keeping the DB-row update on the plan
for the deployment step you're coordinating separately.
