# TOKEN-MAPPING.md — opencti

**Not generated.** First draft written by the agent during Phase 4 of
`implement-tokens-product.prompt.md`; Sandy reviews and arbitrates.

Scope of this pass: `src/components/ThemeDark.ts` and `ThemeLight.ts` only —
static JS/TS wiring of hardcoded hex values to `FDS.colors.<mode>[...]` /
`FDS.gradients.<mode>[...]` from `fds-tokens.generated.ts`. No runtime
CSS-variable sync, no `@filigran/design-system` package dependency added (see
"Deferred to a later phase" below).

Visual delta legend: **none** = identical or case-only diff · **minor** =
perceptible only side-by-side · **notable** = a real, at-a-glance color/shape
shift — these are the ones to scrutinize in the Phase 5 screenshots.

---

## 1. Named constants (`THEME_<MODE>_DEFAULT_*`)

These constants back the platform's admin-customizable theme fields
(`theme_background`, `theme_primary`, etc. in `AppThemeProvider.tsx`) — they
are also exactly the 7 tokens cross-checked against Sandy's reference file
`OPENCTI_TO_FILIGRAN_TOKENS.ts` (all 7 matched exactly, no divergence).

| Constant | FDS token | Old | New (dark) | Delta | New (light) | Delta |
|---|---|---|---|---|---|---|
| `..._BACKGROUND` | `--color-elevation-background-layer-0` | dark `#070d19` / light `#ececf2` | `#070d18` | none | `#f2f2f3` | minor |
| `..._PRIMARY` | `--color-filigran-brand-primary` | dark `#0fbcff` / light `#0015a8` | `#0fbcff` | none | `#0015a8` | none |
| `..._SECONDARY` | `--color-filigran-tonic-primary` | dark `#00f18d` / light `#00bd94` | `#00f0bc` | **notable** | `#00f0bc` | **notable** |
| `..._ACCENT` | `--color-elevation-background-layer-3` | dark `#0f1e38` / light `#dfdfdf` | `#1f3965` | **notable** | `#e4e5e7` | minor |
| `..._PAPER` | `--color-elevation-background-layer-1` | dark `#09101e` / light `#ffffff` | `#0d172b` | minor | `#ffffff` | none |
| `..._TEXT` | `--color-text-default-primary` | dark `#f2f2f3` / light `#18191b` | `#f2f2f3` | none | `#18191b` | none |
| `..._NAV` (local) | `--color-elevation-surface-heading-layer-0` | dark `#070d19` / light `#ffffff` | `#070d18` | none | `#f2f2f3` | **notable** (was pure white) |
| `..._BODY_END_GRADIENT` (local) | `--color-elevation-background-layer-0-gradient` | dark `#08101D` (hardcoded, unwired) / light `#F7F7F7` (hardcoded, unwired) | `#0c1527` | **notable** (see §6 sign-off) | `#ffffff` | **notable** (see §6 sign-off) |

Left untouched (no confident FDS match): `THEME_DARK_DIALOG_BACKGROUND`,
`THEME_LIGHT_DIALOG_BACKGROUND`.

Added `text_color: string` explicit type annotation on both `ThemeDark`/
`ThemeLight` factory functions (was an un-annotated default parameter). This
is a required side-fix, not a token change: `FDS.colors.<mode>[...]` values
are literal-typed in the generated bridge, so TS was narrowing the inferred
parameter type to that literal and rejecting the generic `string` passed in
from `AppThemeProvider.tsx`'s admin-customizable `theme_text_color`.

## 2. Top-level palette — `error` / `warn` / `dangerZone` / `success`

| MUI key | FDS token | Old (dark→light) | New (dark) | New (light) | Delta |
|---|---|---|---|---|---|
| `error.main` | `--color-feedback-error-primary` | `#F14337` → `#F14337` | `#f14337` | `#e51e10` | dark: none · light: **notable** |
| `error.dark` | `--color-feedback-error-secondary` (dark) / `-tertiary` (light) | `#881106` → `#881106` | `#881106` | `#881106` | none |
| `warn.main` | `--color-feedback-warning-primary` | `#E6700F` → `#E6700F` | `#e6700f` | `#e6700f` | none |
| `dangerZone.main` | `--color-feedback-error-primary` | `#F44336` → `#E51E10` | `#f14337` | `#e51e10` | minor / none |
| `dangerZone.light` | `-tertiary` (dark) / `-secondary` (light) | `#F8958C` → `#F8958C` | `#f8958c` | `#f8958c` | none |
| `dangerZone.dark` | `-secondary` (dark) / `-tertiary` (light) | `#881106` → `#881106` | `#881106` | `#881106` | none |
| `dangerZone.text.primary` | same as `.light`/`.dark` respectively | `#F8958C` → `#881106` | `#f8958c` | `#881106` | none |
| `success.main` | `--color-feedback-success-primary` | `#17AB1F` → `#1CA55E` | `#17ab1f` | `#17ab1f` | dark: none · light: **notable** |
| `success.dark` | `-secondary` (dark) / `-tertiary` (light) | `#094E0B` → `#0D7E39` | `#094e0b` | `#117916` | none / minor |

## 3. `ai` (top-level palette)

Tier assignment is **inverted between modes** (verified via exact hex
matches, not assumed): dark mode's `light`=`ia-secondary`/`dark`=`ia-tertiary`;
light mode's `light`=`ia-tertiary`/`dark`=`ia-secondary`.

| MUI key | FDS token | Old (dark / light) | New (dark) | New (light) | Delta |
|---|---|---|---|---|---|
| `ai.main` | `--color-filigran-ia-main` | `#B286FF` / `#5E1AD5` | `#a47af0` | `#651fe5` | minor |
| `ai.light` | dark:`-secondary` · light:`-tertiary` | `#D6C2FA` / `#D6C2FA` | `#e3d6fa` | `#e3d6fa` | minor |
| `ai.dark` | dark:`-tertiary` · light:`-secondary` | `#5E1AD5` / `#3C108C` | `#651fe5` | `#3c108c` | minor / none |

`ai.background` (rgba overlay) left untouched in both modes — no FDS token
covers a translucent panel-overlay concept.

## 4. `severity`

Explicitly delegated by the prompt ("not all are 1:1, document the mapping
you chose"). `none`/`default` have no feedback-family equivalent (neutral /
unset state) and are left untouched.

| Level | FDS token | Old (dark / light) | New (dark) | New (light) | Delta |
|---|---|---|---|---|---|
| `critical` | `--color-feedback-error-primary` | `#EE3838` / `#EE3838` | `#f14337` | `#e51e10` | minor / notable |
| `high` | `--color-feedback-warning-primary` | `#E6700F` / `#E6700F` | `#e6700f` | `#e6700f` | none (exact) |
| `medium` | `--color-feedback-alert-primary` | `#E1B823` / `#E1B823` | `#f2be3a` | `#f2be3a` | **notable** |
| `low` | `--color-feedback-success-primary` | `#16AD34` / `#16AD34` | `#17ab1f` | `#17ab1f` | minor |
| `info` | `--color-feedback-info-primary` | `#1565c0` / `#1565c0` | `#42caff` | `#009edb` | **notable** (was navy, now brighter blue) |

## 5. `designSystem.primary` / `secondary` / `destructive` / `ia`

This block is the main point of the pilot — it existed precisely because
these values used to be hand-copied from Figma exports (added Jan 2026,
consumed by 27+ components via `theme.palette.designSystem.*`; see
`git blame` / `IMPLEMENTATION-LOG.md` for the file list). Family→tier
assignment was verified per family/per mode via exact hex matches, **not**
a single universal rule — see below.

| MUI key | FDS token | Old (dark) | New (dark) | Old (light) | New (light) | Delta |
|---|---|---|---|---|---|---|---|
| `primary.main` | `brand-primary` | `#0FBCFF` | `#0fbcff` | `#0015A8` | `#0015a8` | none |
| `primary.light` | `brand-secondary` | `#B2ECFF` | `#a8e7ff` | `#7587FF` | `#7587ff` | minor / none |
| `primary.dark` | `brand-tertiary` | `#007399` | `#009edb` | `#000842` | `#000842` | **notable** / none |
| `secondary.main` | `tonic-primary` | `#00F1BD` | `#00f0bc` | `#00BD94` | `#00f0bc` | none / **notable** |
| `secondary.light` | `tonic-secondary` | `#BDFFED` | `#bdffed` | *(no match — left `#74E9CA`)* | — | none / n/a |
| `secondary.dark` | `tonic-tertiary` | `#009474` | `#009474` | *(no match — left `#0A8268`)* | — | none / n/a |
| `destructive.main` | `feedback-error-primary` | `#F44336` | `#f14337` | `#E51E10` | `#e51e10` | minor / none |
| `destructive.light` | dark:`-tertiary` light:`-secondary` | `#F8958C` | `#f8958c` | `#F8958C` | `#f8958c` | none |
| `destructive.dark` | dark:`-secondary` light:`-tertiary` | `#881106` | `#881106` | `#881106` | `#881106` | none |
| `ia.main` | `filigran-ia-main` | `#B286FF` | `#a47af0` | `#5E1AD5` | `#651fe5` | minor |
| `ia.light` | dark:`-secondary` light:`-tertiary` | `#D6C2FA` | `#e3d6fa` | `#D6C2FA` | `#e3d6fa` | minor |
| `ia.dark` | dark:`-tertiary` light:`-secondary` | `#5E1AD5` | `#651fe5` | `#3C108C` | `#3c108c` | minor / none |

**Light mode `secondary.light`/`secondary.dark` gap**: unlike dark mode
(where tonic-secondary/tertiary matched the old sub-shades exactly), the
light-mode old values (`#74E9CA`/`#0A8268`) do **not** match
`tonic-secondary`/`tonic-tertiary` (`#bdffed`/`#009474`) at all — left
untouched rather than force a non-match. Flagging in case Sandy wants a
Figma token added for this specific light-mode tonic sub-shade pairing.

## 6. `designSystem.background` / `gradient`

| MUI key | FDS token | Old (dark) | New (dark) | Old (light) | New (light) | Delta |
|---|---|---|---|---|---|---|
| `background.main` | (references `THEME_*_DEFAULT_BACKGROUND`, no duplicate lookup) | `#070D19` | `#070d18` | `#ECECF2` | `#f2f2f3` | none / minor |
| `gradient.background` | `--gradient-background` | `linear-gradient(100.35deg, #070D19 0%, #08101d 100%)` | `linear-gradient(135deg, #070d18 0.0%, #070d18 100.0%)` | `linear-gradient(100.35deg, #ECECF2 0%, #F7F7F7 100%)` | `linear-gradient(135deg, #f2f2f3 0.0%, #f2f2f3 100.0%)` | **notable — see flag below** |
| `gradient.ia` | `--gradient-ia` | `linear-gradient(90deg, #D6C2FA 0.67%, #B286FF 100.67%)` | `linear-gradient(90deg, #e3d6fa 0.0%, #a47af0 100.0%)` | `linear-gradient(90deg, #3C108C 0.67%, #5E1AD5 100.67%)` | `linear-gradient(90deg, #3c108c 0.0%, #651fe5 100.0%)` | minor |
| `gradient.focus` | `--gradient-focus` | `linear-gradient(90deg, #0FBCFF -3.68%, #00F1BD 106.62%)` | `linear-gradient(90deg, #0fbcff 0.0%, #00f0bc 100.0%)` | `linear-gradient(90deg, #0015A8 -3.68%, #00BD94 106.62%)` | `linear-gradient(90deg, #0015a8 0.0%, #00f0bc 100.0%)` | minor |

**✅ Signed off (see `fds-migration/reports/custom-theme-investigation/RAPPORT.md`
for the full investigation).** `gradient.background` (`palette.gradient.*`,
this row) is **dead code** — `MuiCssBaseline`'s actual rendered body/html
background never reads `palette.gradient`, it builds its own
`linear-gradient(100deg, background 0%, getAppBodyGradientEndColor(background)
100%)` inline in `ThemeDark.ts`/`ThemeLight.ts`, driven by the
`..._BODY_END_GRADIENT` constants (see §1 table above). So the flat-fill risk
this row flagged never actually reached the screen through this field; the
*real* bug was that `..._BODY_END_GRADIENT` was hardcoded to an
approximate, unwired value (`#08101D`/`#F7F7F7`) instead of the FDS
`layer-0-gradient` token (`#0c1527`/`#ffffff`), which was already exposed in
the generated bridge (`fds-tokens.generated.ts`) — no lib change needed.

Decision: **real two-stop gradient**, delivered by wiring `..._BODY_END_GRADIENT`
to `FDS.colors.<mode>['--color-elevation-background-layer-0-gradient']` (same
pattern as every other `THEME_*_DEFAULT_*` constant). `getAppBodyGradientEndColor`'s
`lighten(background, 0.05)` branch — the only mechanism that renders a body
gradient for a user's **custom** theme, since no form field lets a user author
that end-stop directly — is left **strictly untouched**; only the
default/fallback constant changes. A DB-column-based approach (adding a
persisted gradient-end field to the `Theme` entity) was considered and
**rejected**: the existing `lighten()` derivation already covers custom themes
correctly (verified live via `getComputedStyle`), so the only real gap was
the unwired fallback constant — no schema change warranted.

This row's `--gradient-background` / `palette.gradient.background` wiring
itself is left as-is (dead code, harmless, out of scope for this sign-off).

`background.bg1`–`bg4`/`disabled` and all of `designSystem.border.*` (both
modes): no confident 1:1 FDS token found — left untouched. Candidates for
"Tokens à créer dans Figma" below if Sandy wants full coverage.

## 7. `designSystem.alert.*`

| Family | FDS token pair | Old (dark) | New (dark) | Old (light) | New (light) | Delta |
|---|---|---|---|---|---|---|---|
| `info.primary` | `feedback-info-primary` | `#4DCCFF` | `#42caff` | `#00719E` | `#009edb` | minor / **notable** |
| `info.secondary` | `feedback-info-secondary` | `#004C66` | `#0079a8` | `#2AB3E0` | `#42caff` | **notable** |
| `success.primary` | `feedback-success-primary` | `#17AB1F` | `#17ab1f` | `#1CA55E` | `#17ab1f` | none / **notable** |
| `success.secondary` | `feedback-success-secondary` | `#094E0B` | `#094e0b` | `#4CD990` | `#72e978` | none / minor |
| `success.tertiary` | `feedback-success-tertiary` | `#75F8B9` | `#91f396` | `#0D7E39` | `#117916` | minor |
| `alert.primary` | `feedback-alert-primary` | `#F2BE3A` | `#f2be3a` | `#F2BE3A` | `#f2be3a` | none |
| `alert.secondary` | `feedback-alert-secondary` | `#573E05` | `#b8870a` | `#F6CE6A` | `#f8d98c` | **notable** / minor |
| `warning.primary` | `feedback-warning-primary` | `#E6700F` | `#e6700f` | `#E6700F` | `#e6700f` | none |
| `warning.secondary` | `feedback-warning-secondary` | `#884106` | `#884106` | `#F8C08C` | `#f8c08c` | none |
| `error.primary` | `feedback-error-primary` | `#F14337` | `#f14337` | `#F14337` | `#e51e10` | none / **notable** |
| `error.secondary` | `feedback-error-secondary` | `#881106` | `#881106` | `#F8958C` | `#f8958c` | none |

## 8. `designSystem.tertiary.*` (raw hue scales)

Confirmed **mode-invariant** in the FDS bridge (identical values in
`colorsDark`/`colorsLight`) — matches the fact that the original code also
had identical `tertiary.*` blocks in both `ThemeDark.ts`/`ThemeLight.ts`.
Every value below matched **exactly**, both modes:

| Family | Shades | FDS value(s) | Delta |
|---|---|---|---|
| `grey` | 400 / 700 / 800 | `#95969d` / `#494a50` / `#313235` | none |
| `darkBlue` | 300 / 500 | `#7587ff` / `#0f2dff` | none |
| `turquoise` | 600 / 800 | `#00bd94` / `#005744` | none |
| `green` | 400 / 600 / 800 | `#41e149` / `#17ab1f` / `#094e0b` | none |
| `red` | 100/200/400/500/600/700 | `#fbcbc5`/`#f8958c`/`#f14337`/`#e51e10`/`#b8180a`/`#881106` | none |
| `orange` | 400 / 500 | `#f2933a` / `#e6700f` | none |
| `yellow` | 400 | `#f2be3a` | none |

`tertiary.blue` (`500: #0099CC`, `900: #003242`) — **no FDS match at all**
in either mode (full scale grep across every `--color-*-blue-*` and
`--color-darkblue-*` token; closest is FDS `blue-500 = #0fbcff`, a
completely different, much brighter color — that's actually the brand
primary, not a blue-scale neighbor). Left untouched. See "Tokens à créer
dans Figma".

## 9. `ee` / `xtmhub` (top-level palette) — deferred, outside this pass's scope

`ee` (`EE_COLOR`) itself was never in scope for this pass (not in
`migration-state.json`'s `migratedZones`) and remains a hand-copied hex
constant in both files (`#00f18d` dark / `#00BD94` light).

`xtmhub` landed via the `master` → `design-system/current` sync merge on
2026-07-27 (commit `b1f6459` / PR #17308-#17309, "rework Filigran Experience
screen with hero-style EE and XTM Hub cards"), added right next to `ee` in
both `ThemeDark.ts` and `ThemeLight.ts`, plus the corresponding
`ExtendedPaletteOptions` entry in `Theme.d.ts`:

| MUI key | FDS token | Value (dark) | Value (light) | Delta |
|---|---|---|---|---|
| `xtmhub.main` | *(none — hardcoded)* | `#00f1bd` | `#00f1bd` (same literal in both modes) | n/a — no FDS wiring attempted |

Source comment in both files: "Aligned with the OpenAEV xtmhub token so the
Filigran Experience screens share the same accent on both platforms."

**Not tokenized now, by design.** `xtmhub` is a sibling of `ee` in the same
"platform accent" family — tokenizing it in isolation before `ee` itself is
migrated would produce an inconsistent half-migrated pair. Revisit both
together once `palette.ee` is picked up in a future migration pass (check
whether FDS has/gets an equivalent token before hand-copying a new hex).

---

## Balayage de complétude (câblé / en dur / dérivé)

Audit exhaustif, propriété par propriété, des 3 fichiers non-générés
touchés (`ThemeDark.ts`, `ThemeLight.ts`, `theme-constants.ts`) :
[`fds-migration/reports/constants-completeness-sweep/RAPPORT.md`](reports/constants-completeness-sweep/RAPPORT.md).
Couvre aussi les zones hors du périmètre §1-8 (palette décorative diverse,
`components.*`, `tag`, `typography`, `button`). Un constat en a émergé et a
été arbitré et fixé : `leftBar.popoverItem` (valeur fantôme du même piège
1-caractère que le fix background) est désormais câblé sur
`THEME_*_DEFAULT_BACKGROUND`.

## Tokens à créer dans Figma

Confirmed gaps — no FDS token found after an exhaustive grep of the
generated bridge (`fds-tokens.generated.ts`, both `colorsDark`/`colorsLight`
blocks) and the full raw hue scales. Four of the bullets below (`tertiary.blue`,
`border.*`, `background.bg1-4/disabled`) are formalized with dark/light values,
usage sites, and cross-product framing in the "Pending design arbitration"
section further below.

- `designSystem.tertiary.blue` (`#0099CC` / `#003242`) — both modes,
  identical values, no scale neighbor at all.
- `designSystem.border.{main,border1,border2}` — both modes, no FDS
  "border" concept currently exists in the token set.
- `designSystem.background.{bg1,bg2,bg3,bg4,disabled}` — both modes, no
  1:1 elevation-layer match found (only `background.main` matched, via the
  existing `THEME_*_DEFAULT_BACKGROUND` constant).
- `designSystem.secondary.{light,dark}` in **light mode only** — the old
  values (`#74E9CA`/`#0A8268`) don't match `tonic-secondary`/`tonic-tertiary`
  the way they do in dark mode; flagged above in section 5.
- Typography scale (`h1`-`h4`, `body1`/`body2`, `overline`) — FDS scalars use
  px-string units with a different step count than OpenCTI's current rem-based
  scale; `h5`/`h6` coincidentally already match FDS numerically so needed no
  change. Left the rest untouched rather than force a mismatched mapping —
  **this decision hasn't been explicitly confirmed with Sandy yet**, flagging
  here for Phase 5 sign-off alongside the color deltas.

## Pending design arbitration — no existing FDS token (all 5 resolved 2026-07-28)

Five confirmed color families where the original wiring pass found **no
matching FDS token at all** (not a naming mismatch, not a "close enough"
candidate — an actual absence, verified by grepping every
`--color-*`/`--gray-*`/`--darkblue-*` entry of both `colorsDark`/`colorsLight`
blocks in the generated bridge). **Update 2026-07-28**: the lib's
`TOKEN-MIGRATION-GUIDE.md` now has a mapping for all five (2 added directly by
lib PR #52 — border-secondary and `primary.light` root-palette rows — the
other 3 were already present from an earlier, unattributed lib change, not
#52 itself). Re-verified each against the current guide/bridge and **wired
all 5** (see each subsection). 4 of 5 use the guide's proposed token exactly;
the 5th (`tertiary.blue`, §2) uses the guide's proposed token's **opaque
sibling** instead of the exact token proposed — flagged for Thibault's review
in §2, not applied silently. Tracked (now empty of these 5) in
`migration-state.json`'s `notMigrated` array.

**Cross-product significance**: the same five gaps exist in OpenAEV's theme
files. The resolutions below are the tokens OpenAEV should use for parity;
the `tertiary.blue` deviation (§2) should be reviewed once, here, rather than
re-litigated per product.

### 1. `severity.none` / `severity.default` — ✅ RESOLVED 2026-07-28

Neutral/unset severity state — no member of the FDS feedback family
(`error`/`warning`/`alert`/`success`/`info`) represents "no severity", so
there was nothing to map to until now.

| Key | Dark (before → after) | Light (before → after) |
|---|---|---|
| `severity.none` | `#424242` → `--color-feedback-neutral-primary` (`#7a9cd6`) | `#424242` → `--color-feedback-neutral-primary` (`#afb0b6`) |
| `severity.default` | `#1C2F49` → `--color-feedback-neutral-primary` (`#7a9cd6`) | `#DDE1FE` → `--color-feedback-neutral-primary` (`#afb0b6`) |

Both keys now resolve to the **same** token (both are semantically "no
severity set") — `none` and `default` become visually identical for the first
time (previously two different hardcoded colors, coincidentally). This is the
mapping the lib guide proposes; flagged here for visibility, not held back,
since it's a deliberate semantic consolidation rather than an accident.

Usage: `ItemSeverity.tsx`, `ItemPriority.tsx`, `ItemCvssScore.tsx` (×2),
`ItemMarkings.tsx`.

### 2. `designSystem.tertiary.blue.500` / `.900` — ✅ RESOLVED 2026-07-28 (deviates from guide — flagged to Thibault)

Two rungs of the raw hue-scale table with no FDS scale neighbor — every other
`tertiary.*` family (`grey`, `darkBlue`, `turquoise`, `green`, `red`, `orange`,
`yellow`) matched an FDS scalar exactly; `blue` was the sole exception.

| Key | Dark (before → after) | Light (before → after) |
|---|---|---|
| `tertiary.blue.500` | `#0099CC` → `--color-feedback-info-secondary` (`#0079a8`) | `#0099CC` → `--color-feedback-info-secondary` (`#42caff`) |
| `tertiary.blue.900` | `#003242` → `--color-feedback-info-secondary` (`#0079a8`) | `#003242` → `--color-feedback-info-secondary` (`#42caff`) |

**⚠ Deviation from the guide, for Thibault's review**: `TOKEN-MIGRATION-GUIDE.md`
(lines 109-110) proposes `--color-feedback-info-secondary-transparency` for
both rungs, not the plain `--color-feedback-info-secondary` used here. Checked
both in the bridge: the guide's proposed token resolves to an **8-digit hex
with ~30% alpha** (dark `#0079a84d`, light `#42caff4d`, a
`color-mix(..., transparent)` token) — a translucent color — whereas
`.blue[500]` has a real, opaque consumer (`ScaleBar.tsx`, a configurable
scale/decay-chart rail-color default) that would visibly wash out/blend with
the page background if wired to a translucent fill. **`--color-feedback-info-secondary`
is the exact opaque sibling of the guide's proposed token** (same base color,
`theme.css` lines 145/550/651, just without the `color-mix` alpha applied) —
same semantic family the guide already chose, opacity fixed.

Two residual trade-offs, both considered and accepted as lower-risk than the
alpha issue: (a) `.500`/`.900` now resolve to the **same** value — the guide
itself already flags `.900` as *"⚠ Dormant (0 consommateur produit) —
candidat à retrait plutôt qu'à mapping"*, independently confirmed here (only
`.500` has live consumers: `ScaleBar.tsx`, `CustomViewsSettingsDataTable.tsx`
icon color) — so this collapse has zero visible impact today; (b) unlike the
rest of the mode-invariant `tertiary.*` family, this token is
mode-*dependent* (dark `#0079a8` vs. light `#42caff`), a real, larger-than-
before shift for the one live consumer (`.500`) in both modes — current
`#0099CC` sits roughly between the two new mode values. This is the one
point worth a second look from design/Thibault: a mode-invariant scalar
alternative exists and stays closer to the current value in both modes —
`FDS.scalars['--blue-600']` = `#009edb` for `.500` (Δ≈imperceptible vs.
current, both modes) and `FDS.scalars['--blue-900']` = `#003042` for `.900`
(2/255 delta) — flagged here in case the opaque-but-mode-dependent choice
made in this pass is reconsidered.

Usage: `ScaleBar.tsx` (`.blue[500]`, default rail-segment fill),
`CustomViewsSettingsDataTable.tsx` (`.blue.500`, `Insights` icon color).
`.900` has no current consumer (per the guide's own note and independently
confirmed by grep).

### 3. `designSystem.background.bg1`–`bg4` / `.disabled` — ✅ RESOLVED 2026-07-28

Five elevation-adjacent surfaces beyond `background.main` (the only member of
this block with an FDS/`THEME_*_DEFAULT_BACKGROUND` match). The bridge
resolves per-layer elevation tokens distinctly, so each `bgN` maps to its own
`-layer-(N-1)` key rather than collapsing to one shared value.

| Key | Dark (before → after) | Light (before → after) |
|---|---|---|
| `background.bg1` | `#0C1524` → `--bg-elevation-default-layer-0` (`#070d18`) | `#F7F7F7` → `--bg-elevation-default-layer-0` (`#f2f2f3`) |
| `background.bg2` | `#0D182A` → `--bg-elevation-default-layer-1` (`#0d172b`) | `#FFFFFF` → `--bg-elevation-default-layer-1` (`#ffffff`, exact match) |
| `background.bg3` | `#253348` → `--bg-elevation-default-layer-2` (`#13213e`) | `#E4E4E4` → `--bg-elevation-default-layer-2` (`#f4f4f6`) |
| `background.bg4` | `#1C2F49` → `--bg-elevation-default-layer-3` (`#1f3965`) | `#DDE1FE` → `--bg-elevation-default-layer-3` (`#e4e5e7`) |
| `background.disabled` | declared `#363B46` → `--bg-elevation-disabled` (`#18191b`) — **NOT applied**: `ThemeDark.ts` still holds the literal | declared `#DFDFDF` → `--bg-elevation-disabled` (`#c8d6ee`) — **NOT applied**: `ThemeLight.ts` still holds the literal |

Usage: `bg1` → `TopBar.tsx`; `bg4` → `DraftToolbar.tsx`. `bg2`/`bg3` are
declared on the theme with no direct consumer found in this sweep — still real,
now-tokenized properties that could be consumed at any point. `disabled` is the
exception on both counts (corrected 2026-08-24): the mapping above was declared
but never applied, and it does have a consumer — `getDisabledSx` in
`components/common/button/Button.utils.ts` paints it as the background of a
disabled primary Button. Rewiring it is a rendered change, not a no-op.

### 4. `designSystem.border.main` / `.border1` / `.border2` — ✅ RESOLVED 2026-07-28

Neutral/grey border tones — no "border" concept currently exists in the FDS
token set (as opposed to `palette.border.*`, the top-level MUI border block,
which is a separate, already-classified property).

| Key | Dark (before → after) | Light (before → after) |
|---|---|---|
| `border.main` | `#2B3447` → `--border-elevation-default` (`#3665b4`) | `#D2D2D2` → `--border-elevation-default` (`#7a7c85`) |
| `border.border1` | `#424751` → `--border-elevation-subtle` (`#1f3965`) | `#C2C2C2` → `--border-elevation-subtle` (`#cacbce`) |
| `border.border2` | `#1C253A` → `--border-elevation-subtle` (`#1f3965`) | `#999797` → `--border-elevation-subtle` (`#cacbce`) |

`border1`/`border2` now resolve to the **same** token (both previously
different hardcoded grays); per the completeness sweep, neither has a live
consumer today, so this consolidation has zero current visual impact.

Usage: `main` → `StixCoreObjectQuickSubscription.tsx`. `border1`/`border2` are
declared but no direct consumer was found in this sweep.

### 5. `primary.light` fallback (`#B2ECFF` dark, `#7587FF` light) — ✅ RESOLVED 2026-07-28 (both modes)

Top-level `palette.primary.light` (not `designSystem.primary.light`, which
**is** wired to `brand-secondary` — see section 5 above) falls back to a
hardcoded literal when no DB-override `primary` is supplied. Both modes now
reference `--color-filigran-brand-secondary`:

| Key | Dark (before → after) | Light (before → after) |
|---|---|---|
| `primary.light` (fallback) | `#B2ECFF` → `--color-filigran-brand-secondary` (`#a8e7ff`) | `#7587FF` → `--color-filigran-brand-secondary` (`#7587ff`, exact match) |

⚠ **Dark-mode note**: the lib guide itself flags this as an *approximate*
match ("`#B2ECFF`≈`blue-200`"), not exact — `#a8e7ff` is a real, if minor,
color shift from the current `#B2ECFF` (R -10, G -5, B 0). Light mode is an
**exact** match (`#7587FF` = `#7587ff`), confirming the pre-existing note
below that it was "a wiring opportunity, not a gap" — now wired for
consistency with the dark-mode fix.

No inline code comment admitted this one (unlike gaps 1, 3, 4 above) — it
surfaced during the completeness sweep (`fds-migration/reports/constants-completeness-sweep/RAPPORT.md`,
section 9.1: *"`primary.light` (fallback without override) — 🔴 HARDCODED
(the `main` is 🟢/🟡, this `.light` fallback is not)"*), not from a
pre-existing code annotation.

Usage: `Button.utils.ts` (×2, `focus` color), `ImportFilesDropzone.tsx`
(drag-over background tint).

## Deferred to a later phase (confirmed with Sandy)

`OPENCTI_TO_FILIGRAN_TOKENS.ts` (Sandy's reference file) defines a
`useFiligranTokensSync` hook that pushes admin theme customizations into
runtime CSS custom properties on `<html>`. Investigated and confirmed:
`@filigran/design-system` is **not** currently a dependency of
`opencti-front`, no `theme.css` is imported anywhere, and no `.dark`/`.light`
class is ever applied (the existing `useDocumentThemeModifier` only sets a
`data-theme` attribute on `<body>`, for CKEditor, unrelated to FDS). Sandy
confirmed this pilot should be limited to the static JS wiring done above;
the CSS-variable runtime sync is real follow-up work, not an oversight.

### Generator output isn't lint-conformant (lib-side follow-up)

`fds-tokens.generated.ts` fails `opencti-front`'s ESLint config as-is: 1216
problems, 1211 of them `@stylistic/quotes` (the generator emits
double-quoted string literals; this codebase's style requires single
quotes), plus a handful of `comma-dangle`/`indent`/naming-convention/import
findings. Worked around on the consuming side for now — added
`fds-tokens.generated.ts` + `fds-tokens.generated.meta.json` to
`opencti-front/eslint.config.js`'s `ignores` (same treatment as
`__generated__/**`, the Relay-generated files), since hand-fixing or
`--fix`-ing a generated file is pointless: the next regeneration would
reintroduce every violation.

**Real fix belongs in the `mui-bridge` generator** (separate lib micro-PR,
not urgent, not blocking this PR): either emit single-quoted strings (and
match this repo's other stylistic conventions — trailing commas, indent)
directly, or emit a `/* eslint-disable */` header so consuming repos don't
need their own ignore-list entry. Either approach removes the need for
every downstream consumer to special-case this file in their own lint
config.

---

*All FDS values above are taken from `fds-tokens.generated.ts`
(themeCssHash `sha256:6e9d0f45a1c4f762b83bd1908f04ed4d43809527ee8b43998af52aed719c5e11`).
If that file is regenerated with a different upstream `theme.css`, re-verify
this table rather than assuming it still holds.*
