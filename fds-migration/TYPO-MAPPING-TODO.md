# Typography mapping — arbitration TODO

Working table for the typography arbitration (Sandy + Thibault). This is
**not** a wiring plan — no typography tokens have been touched in this pilot.
Colors/spacing/body are wired (see `TOKEN-MAPPING.md`); typography is
intentionally left as documented debt, per the pilot's scope.

**How to read this table**: one row per variant of OpenCTI's current MUI
`typography` theme config (`ThemeDark.ts`/`ThemeLight.ts` — identical values
in both modes, only colors differ). The "Named Style FDS" column is a
**value-proximity suggestion only** — sorted primarily by closest font-size,
then noting weight/family/line-height gaps precisely. It is not a
recommendation to adopt; the **Decision** column is left empty for you to
fill in with Thibault.

A methodology note on ties and false friends, found while building this:
- Where two FDS sizes are equidistant from the OpenCTI value, both are
  listed as candidates.
- Some MUI variant *names* coincide with FDS style *names* (e.g. MUI
  `caption` vs FDS `content-caption`) but are **not** the closest value
  match — flagged explicitly where this happens, so the name doesn't bias
  the decision.
- `button` and `overline` have 0 direct `variant="..."` usages in
  `opencti-front` (grep found none), but `button` typography is still
  applied implicitly to every `MuiButton` by MUI's defaults — it's not
  dead, just never invoked via an explicit Typography variant.

## Mapping table

| Variant MUI | Valeurs actuelles OpenCTI (font/size/weight/line-height) | Occurrences approx. (`variant=` grep, opencti-front) | Named Style FDS le plus proche (suggestion + écart précis) | Décision |
|---|---|---|---|---|
| `h1` | Geologica, 22px, weight 400 (regular), line-height: MUI default (browser/user-agent, not set) | 7 (7 fichiers) | Tie between `header-heading-md` (20px/500/Geologica) and `header-heading-lg` (24px/500/Geologica) — both ±2px. **Écart** commun aux deux : weight 400 vs 500 (aucun style Header FDS n'est en weight 400 sauf aucun — le plus proche en poids reste 500). | *(vide)* |
| `h2` | Geologica, 16px, weight 500 | 25 (16 fichiers) | Size-closest: `header-heading-sm` (16px/**700**/Geologica) — écart : poids 500 vs 700 (2 crans). Weight-closest: `header-heading-md` (**20px**/500/Geologica) — écart : 4px vs 0 sur le poids. Trade-off à trancher. | *(vide)* |
| `h3` | Geologica, 13px, weight 400 | 84 (33 fichiers) | `header-heading-xs` — 14px/600/Geologica — écart : 1px (13 vs 14), poids 400 vs 600 (2 crans). | *(vide)* |
| `h4` | **IBM Plex Sans** (pas Geologica, contrairement aux autres h*), 12px, weight 500, height:15 (contrainte de layout custom) | 38 (22 fichiers) | `content-body-compact-medium` — 12px/500/IBM Plex Sans/leading 115% — **match quasi-exact** (taille + poids + famille tous alignés, seul le `height:15` custom n'a pas d'équivalent FDS car ce n'est pas une valeur typographique). | *(vide)* |
| `h5` | Geologica, 16px, weight 700 | 7 (7 fichiers) | `header-heading-sm` — 16px/700/Geologica — **match exact** (taille + poids + famille). | *(vide)* |
| `h6` | Geologica, 14px, weight 600 | 35 (14 fichiers) | `header-heading-xs` — 14px/600/Geologica — **match exact** (taille + poids + famille). | *(vide)* |
| `subtitle1` | Non surchargé → défaut MUI : IBM Plex Sans (police par défaut du thème), 16px (1rem), weight 400, line-height 1.75 | 9 (7 fichiers) | Aucun style Content FDS n'atteint 16px (max Content = 14px). Size-exact mais famille/poids faux : `header-heading-sm` (16px/700/**Geologica**) — écart : famille (Plex vs Geologica) + poids (400 vs 700). Alternative Content la plus proche : `content-body-base-bold` (14px/600/Plex) — écart : 2px + poids. **Cas ambigu, pas de bon candidat.** | *(vide)* |
| `subtitle2` | Non surchargé pour la famille → IBM Plex Sans, 18px, weight 400 | 8 (5 fichiers) | Aucun style FDS à 18px exactement. Tie: `header-heading-md` (20px/500/Geologica) et `header-heading-sm` (16px/700/Geologica), tous deux ±2px avec famille ET poids qui ne collent pas (Content ne monte qu'à 14px). **Cas ambigu, plus gros écart du tableau.** | *(vide)* |
| `body1` | IBM Plex Sans, 14.4px (0.9rem), weight 400 (défaut), line-height : non surchargé (défaut MUI ≈150%) | 32 (13 fichiers) | `content-body-base` — 14px/400/Plex/leading **115%** — taille et poids quasi-exacts (écart 0.4px), mais écart de line-height notable : ≈150% (défaut MUI actuel) vs 115% (FDS). | *(vide)* |
| `body2` | IBM Plex Sans, 12.8px (0.8rem), weight 400 (défaut), line-height 19.2px (1.2rem = 150% du fontSize) | 71 (45 fichiers) | `content-body-compact` — 12px/400/Plex/leading **115%** — taille et poids proches (écart 0.8px), écart de line-height : 150% actuel vs 115% FDS (même écart que body1). | *(vide)* |
| `caption` | Non surchargé → défaut MUI : IBM Plex Sans, 12px (0.75rem), weight 400, line-height 1.66, letter-spacing 0.033em | 23 (16 fichiers) | ⚠️ **Faux ami de nommage** : le style FDS nommé `content-caption` est à 10px, alors que `content-body-compact` (12px/400/Plex) est en fait plus proche en valeur (écart 0px vs 2px). Suggestion par proximité stricte : `content-body-compact`. Le style *nommé* pareil (`content-caption`, 10px/400/Plex) reste l'option sémantique si vous préférez aligner les noms plutôt que les valeurs. | *(vide)* |
| `button` | Non surchargé → défaut MUI : IBM Plex Sans, 14px (0.875rem), weight 500, uppercase, letter-spacing 0.029em | 0 usages directs (`variant=`) — mais appliqué implicitement à tout `MuiButton` | `content-button` — 14px/**600**/Plex/leading 115% — taille et famille exactes, écart de poids : 500 vs 600 (1 cran). Les noms coïncident, bon signe. | *(vide)* |
| `overline` | Non surchargé pour taille → défaut MUI 12px (0.75rem), weight 500 (surchargé), + uppercase/letter-spacing (comportement MUI par défaut) | 0 usages directs (`variant=`) | `content-body-compact-medium` — 12px/500/Plex/leading 115% — **match exact** sur taille + poids + famille (le uppercase/letter-spacing est un comportement de composant MUI, pas une valeur de style FDS, donc hors périmètre de comparaison). | *(vide)* |

## FDS Named Styles — full reference (for arbitration without opening Figma)

Font families: `Geologica` (`--font-sans-geologica`) for the **Header**
group, `"IBM Plex Sans"` (`--font-sans-plex`) for the **Content** group.
Weights: regular=400, medium=500, semibold=600, bold=700.
Tracking (letter-spacing): `normal` = 0.75% for all styles below except
`header-jumbo` (1.79%, listed explicitly).

### Header group (Geologica)

| Style | Size | Weight | Line-height | Tracking | Figma use case (RULE-01/03) |
|---|---|---|---|---|---|
| `header-jumbo` | 42px | medium (500) | tight (120%) | 1.79% | Big number — KPIs, counters, dashboard metrics. NOT for editorial titles. |
| `header-heading-2xl` | 32px | medium (500) | tight (120%) | normal (0.75%) | Title — display/title levels |
| `header-heading-xl` | 28px | medium (500) | tight (120%) | normal (0.75%) | Title — display/title levels |
| `header-heading-lg` | 24px | medium (500) | tight (120%) | normal (0.75%) | Title — display/title levels |
| `header-heading-md` | 20px | medium (500) | tight (120%) | normal (0.75%) | Title — display/title levels |
| `header-heading-sm` | 16px | **bold (700)** | tight (120%) | normal (0.75%) | Title — display/title levels |
| `header-heading-xs` | 14px | semibold (600) | tight (120%) | normal (0.75%) | Smallest title level |

### Content group (IBM Plex Sans)

| Style | Size | Weight | Line-height | Tracking | Figma use case (RULE-02/04/05) |
|---|---|---|---|---|---|
| `content-highlight` | 14px | semibold (600) | 115% | normal (0.75%) | Important notification / emphasis in body text. NOT a heading substitute. |
| `content-button` | 14px | semibold (600) | 115% | normal (0.75%) | Exclusive style for interactive CTAs. NOT for non-interactive text. |
| `content-body-base` | 14px | regular (400) | 115% | normal (0.75%) | Base body text, regular weight default |
| `content-body-base-medium` | 14px | medium (500) | 115% | normal (0.75%) | Body text emphasis variant |
| `content-body-base-bold` | 14px | semibold (600) | 115% | normal (0.75%) | Body text highlight variant |
| `content-body-base-link` | 14px | medium (500) | 115% | normal (0.75%) | Inline hyperlink style (underline). NOT an interactive component state. |
| `content-body-compact` | 12px | regular (400) | 115% | normal (0.75%) | Secondary/compact body text, regular weight default |
| `content-body-compact-medium` | 12px | medium (500) | 115% | normal (0.75%) | Secondary text emphasis variant |
| `content-body-compact-bold` | 12px | semibold (600) | 115% | normal (0.75%) | Secondary text highlight variant |
| `content-body-compact-link` | 12px | medium (500) | 115% | normal (0.75%) | Compact inline hyperlink (underline). NOT an interactive state. |
| `content-caption` | 10px | regular (400) | 115% | normal (0.75%) | Tertiary text / legend — smallest size in the scale |

Source: `packages/filigran-design-system/src/tokens/theme.css` (generated
tokens) cross-referenced with `scripts/templates/llms-full-typography-intent.md`
(Figma designer-intent annotations, node 2495-15295) in the design-system
repo. Sizes trace back to the raw scale: `--text-1`=10px … `--text-12`=64px
(only 1–10 are used by named typography styles; 2, 3, 4, 5, 6, 7, 8, 10
appear above).
