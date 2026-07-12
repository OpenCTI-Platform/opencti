# Balayage de complétude — câblé / en dur / dérivé

Audit exhaustif de `ThemeDark.ts`, `ThemeLight.ts` et `theme-constants.ts`
(les 3 fichiers non-générés touchés par le pilote) : chaque valeur de couleur
(et, en section 9, chaque valeur de typo/spacing) est classée dans une des
3 catégories ci-dessous. Objectif : donner aux devs OpenCTI qui relisent la
PR une vue d'ensemble immédiate de ce qui est réellement câblé au pont FDS,
ce qui reste en dur (dette ou absence de correspondance), et ce qui est
calculé dynamiquement.

Lecture seule — aucun fix appliqué ici. Les constats de la section 8
("points relevés pour arbitrage") ne sont **pas** corrigés : ce sont des
propositions, à trancher par Sandy.

## Légende

- 🟢 **CÂBLÉ** — référence directement `FDS.colors.<mode>[...]`,
  `FDS.gradients.<mode>[...]` ou `FDS.scalars[...]` (le pont généré depuis
  `theme.css`).
- 🟡 **DÉRIVÉ** — calculé à l'exécution à partir d'une valeur déjà classée,
  via `lighten()` / `darken()` / `alpha()` / `hexToRGB()`, ou correspond au
  paramètre de surcharge utilisateur lui-même (`background`, `paper`, `nav`,
  `primary`, `secondary`, `accent` — le mécanisme des thèmes custom, qui
  reste strictement intact et hors périmètre de recâblage).
- 🔴 **EN DUR** — chaîne littérale (hex ou `rgba(...)`) sans lien avec le
  pont FDS, ni calculée depuis une valeur câblée.

## Méthode

Comptage par grep sur les 2 fichiers théoriquement dans le périmètre couleur
du pilote (`git diff origin/design-system/current..HEAD` confirme que seuls
`ThemeDark.ts`, `ThemeLight.ts`, `theme-constants.ts` +
`fds-tokens.generated.{ts,meta.json}` ont bougé) :

| Fichier | Réfs `FDS.*` | Appels dérivation (`lighten/darken/alpha/hexToRGB`) | Lignes avec littéral hex |
|---|---|---|---|
| `ThemeDark.ts` | 69 | 15 | 58 |
| `ThemeLight.ts` | 67 | 17 | 66 |

`FDS.scalars` (typo/spacing/radius/shadow, mode-invariant) : **0 référence**
dans les deux fichiers — confirme que la dette typo/spacing mentionnée dans
la description de la PR est réelle et non entamée (section 9).

---

## 1. Constantes nommées (`THEME_<MODE>_DEFAULT_*`)

Déjà table détaillée dans `TOKEN-MAPPING.md` §1 (avec les valeurs old→new).
Classification complétude :

| Constante | Classe | Note |
|---|---|---|
| `..._BACKGROUND` | 🟢 CÂBLÉ | |
| `..._PRIMARY` | 🟢 CÂBLÉ | |
| `..._SECONDARY` | 🟢 CÂBLÉ | |
| `..._ACCENT` | 🟢 CÂBLÉ | |
| `..._PAPER` | 🟢 CÂBLÉ | |
| `..._TEXT` | 🟢 CÂBLÉ | |
| `..._NAV` | 🟢 CÂBLÉ | |
| `..._BODY_END_GRADIENT` | 🟢 CÂBLÉ | fixé cette itération (était en dur) |
| `..._DIALOG_BACKGROUND` | 🔴 EN DUR | pas de token FDS confident identifié ; assumé (§8) |

## 2–5. `error` / `warn` / `dangerZone` / `success` / `ai` / `severity` / `designSystem.{primary,secondary,destructive,ia,alert}`

Déjà détaillées avec diff old→new dans `TOKEN-MAPPING.md` §2-5, §7.
Classification complétude : **100 % 🟢 CÂBLÉ**, à deux exceptions déjà
documentées et assumées dans `TOKEN-MAPPING.md` :
- `severity.none` / `severity.default` — 🔴 EN DUR (états neutres, pas
  d'équivalent FDS).
- `designSystem.secondary.light` / `.dark` (**light theme uniquement**) —
  🔴 EN DUR (`#74E9CA` / `#0A8268`) : commenté dans le code, pas de teinte
  FDS "tonic" qui varie par mode correspondant à ces anciennes valeurs.

## 6. `designSystem.background` / `designSystem.gradient`

| Propriété | Classe | Note |
|---|---|---|
| `background.main` | 🟢 CÂBLÉ | = `THEME_*_DEFAULT_BACKGROUND` |
| `background.bg1`-`bg4`, `.disabled` | 🔴 EN DUR ×5 | commenté "no confident 1:1 FDS token found" |
| `gradient.background` / `.ia` / `.focus` | 🟢 CÂBLÉ ×3 | `FDS.gradients.<mode>[...]`, chaînes `linear-gradient()` complètes |

## 7. `designSystem.tertiary.*` (échelles de teintes brutes)

40 clés numériques (`grey.400/700/800`, `blue.500/900`, `darkBlue.300/500`,
`turquoise.600/800`, `green.400/600/800`, `red.100-700`,
`orange.400/500`, `yellow.400`) : **🟢 CÂBLÉ sauf `blue.500`/`blue.900`**
(🔴 EN DUR, commenté "no FDS scale matches these two values").

## 8. `border` / `designSystem.border`

| Propriété | Classe |
|---|---|
| `designSystem.border.main/.border1/.border2` | 🔴 EN DUR ×3 (commenté, pas de token trouvé) |
| `palette.border.primary` | 🟡 DÉRIVÉ (`hexToRGB(primary\|\|défaut câblé, 0.3)`) |
| `palette.border.secondary/.main` | 🔴 EN DUR |
| `palette.border.pagination/.paper` (+ `lightBackground` en light) | 🟡 DÉRIVÉ (`hexToRGB()` d'un littéral en dur `#ffffff`/`#000000`) |

---

## 9. Zones hors couverture `TOKEN-MAPPING.md` §1-8 (le reste du fichier)

Ces zones n'étaient **pas** dans le périmètre couleur documenté §1-8 —
balayage exhaustif ci-dessous, groupé par nature.

### 9.1 Palette diverse (top-level, hors `designSystem`)

| Propriété | Dark | Light | Classe |
|---|---|---|---|
| `common.white/grey/lightGrey` | `#ffffff`/`#95969D`/`#E4E5E7` | `#ffffff`/`#494A50`/`#AFB0B6` | 🔴 EN DUR ×3 |
| `primary.light` (fallback sans surcharge) | `#B2ECFF` | `#7587FF` | 🔴 EN DUR (le `main` est 🟢/🟡, ce fallback `.light` ne l'est pas) |
| `gradient.main` (top-level, ≠ `designSystem.gradient`) | `#00f18d` | `#00BD94` | 🔴 EN DUR — **duplique littéralement `EE_COLOR`** (même fichier) sans référencer la constante |
| `pagination.main` | `#ffffff` | `#000000` | 🔴 EN DUR |
| `chip.main` | `#ffffff` | `#000000` | 🔴 EN DUR |
| `ai.contrastText` | `#000000` | `#000000` | 🔴 EN DUR |
| `ai.background` | `rgba(28,47,73,0.94)` | `rgba(221,225,254,0.94)` | 🔴 EN DUR |
| `ee.main` (`EE_COLOR`) | `#00f18d` | `#00BD94` | 🔴 EN DUR |
| `ee.contrastText` | `THEME_DARK_DEFAULT_TEXT` | `#F2F2F3` (light : en dur, pas la constante) | dark 🟢 CÂBLÉ / light 🔴 EN DUR (incohérence mineure entre les 2 fichiers) |
| `ee.background`/`.lightBackground` | `hexToRGB(EE_COLOR, .2/.08)` | idem | 🟡 DÉRIVÉ (d'une base en dur) |
| `background.shadow` | `rgba(200,200,200,.15)` | `alpha('#000000',.15)` | 🔴 EN DUR |
| `background.secondary` (fallback) | `#0C1524` | `#FFFFFF` | 🔴 EN DUR — **duplique le fallback de `MuiSelect`/`MuiAutocomplete` outlined** (voir 9.3) |
| `background.drawer` (fallback) | `#0f1d34` | `#FFFFFF` | 🔴 EN DUR |
| `background.disabled` | `#363B46` | `#DFDFDF` | 🔴 EN DUR |
| `background.gradient.start` | = `default` | = `default` | 🟢/🟡 (hérite de `default`) |
| `background.gradient.end` | `getAppBodyGradientEndColor()` | idem | 🟢 CÂBLÉ (défaut, fixé cette itération) / 🟡 DÉRIVÉ (`lighten()`, thème custom) |
| `text.tertiary/.light/.disabled` | `#848592`/`#AFB0B6`/`#75829A` | `#717172`/`#494A50`/`#6E7788` | 🔴 EN DUR ×3 |
| `leftBar.header.itemBackground`/`.hover` | `#253348` (×2, dupliqués) | `#ECECF2`/`#0015A81A` | 🔴 EN DUR |
| `leftBar.popoverItem` | `#070D19` | `#ECECF2` | 🔴 EN DUR — **voir constat 8.1 ci-dessous, arbitrage recommandé** |
| `leftBar.text` | `#F2F2F3` | `#18191B` | 🔴 EN DUR — **duplique exactement `--color-text-default-primary` câblé** (`THEME_*_DEFAULT_TEXT`), sans le référencer |

### 9.2 `tag` / `typography` / `button`

- `tag.overflowColor` : 🟡 DÉRIVÉ/🟢 CÂBLÉ (`primary || THEME_*_DEFAULT_PRIMARY`).
- `typography.*` (fontFamily ×2 familles, fontSize/lineHeight/fontWeight sur
  body1/body2/overline/h1-h6/subtitle2, ~30 valeurs) : **100 % 🔴 EN DUR**.
  `FDS.scalars` expose pourtant `--font-sans-plex`/`--font-sans-geologica`,
  `--text-*`, `--font-weight-*`, `--leading-*` — non consommés. Confirme la
  dette typo déjà actée comme hors périmètre.
- `button.sizes.default/.small.*` (height/padding/fontSize/fontWeight/
  lineHeight/iconSize, ~16 valeurs) : **100 % 🔴 EN DUR**. `FDS.scalars`
  expose des `--radius-*`/`--shadow-*` non consommés ici. Dette spacing,
  même statut.
- **Non touché par le diff du pilote** (`git diff` confirmé) : ces deux
  blocs existaient déjà tels quels avant le pilote — ce n'est pas une
  régression, c'est la dette documentée dans `TOKEN-MAPPING.md`
  ("Deferred to a later phase").

### 9.3 `components.*` (style overrides littéraux touchant des couleurs)

Listing groupé (non exhaustif ligne à ligne — ce sont des styles CSS
décoratifs, pas des tokens de palette) :

- `MuiButton` : `hexToRGB('#ffffff', .15/.05)` → 🟡 DÉRIVÉ (base 🔴 en dur).
- `MuiDialog.paper.backgroundColor` (fallback) : `#0F1D34` (dark) /
  `#FFFFFF` (light) → 🔴 EN DUR — **duplique exactement
  `THEME_*_DIALOG_BACKGROUND`** sans la référencer.
- `MuiToggleButtonGroup` : bordure `#2B3447`/`#D2D2D2`, focus-ring
  `#BDFFED`/`#7587FF` → 🔴 EN DUR ; sélection `hexToRGB(primary,.25/.15)` →
  🟡 DÉRIVÉ.
- `MuiTooltip` : `rgba(0,0,0,.7)` → 🔴 EN DUR (les deux modes, même valeur).
- `MuiTextField`/`MuiAutocomplete` (label shrink) : `#AFB0B6` (dark) /
  `#494A50`(?) → dark 🔴 EN DUR, **duplique `palette.text.light`**.
- `MuiSelect.outlined`/`MuiAutocomplete .MuiOutlinedInput-root` (fallback
  backgroundColor) : `#0C1524`/`#FFFFFF` → 🔴 EN DUR — **3ᵉ occurrence du
  même littéral que `background.secondary`** (voir 9.1).
- `MuiCssBaseline` : `scrollbarColor`/`background` (gradient) → 🟢/🟡
  (héritent de `background`/`accent`/gradient) ; le reste (ombres
  `rgba(4,8,17,.88)`, bordures `.error` `#F14337`, `react_time_range`
  `#00bcd4`, poignées de resize `rgba(255,255,255,.4)`) → 🔴 EN DUR,
  décoratif, non touché par le diff.
  - Note en passant (**hors périmètre, pré-existant, pas introduit par le
    pilote**) : `.error .react-mde textarea` utilise le littéral
    `#F14337` (rouge du thème **dark**) dans **les deux** fichiers,
    y compris `ThemeLight.ts` où le rouge réellement câblé est `#e51e10`.
    Bug pré-existant sans rapport avec le câblage FDS — signalé pour
    mémoire, pas dans le scope de cette PR.
- `MuiTableCell`/`MuiMenuItem` : bordures `rgba(255,255,255,.15)` (🔴 EN
  DUR) ; sélection `hexToRGB(primary,.24/.32)` (🟡 DÉRIVÉ).

## 10. Seed backend — `theme-constants.ts`

| Champ | Classe | Note |
|---|---|---|
| `theme_background/_paper/_nav/_primary/_secondary/_accent/_text_color` (DARK_DEFAULTS + LIGHT_DEFAULTS, 7×2 = 14 valeurs) | 🔴 EN DUR **mais intentionnel** | package backend, ne peut pas importer `fds-tokens.generated.ts` (frontend) — littéraux recopiés à la main, tenus synchronisés par commentaire + convention (pas de lien programmatique possible entre les deux packages) |
| `theme_logo*`/`theme_login_aside_*` (7×2 = 14 valeurs) | — | chaînes vides, hors périmètre (pas de couleur) |

---

## Constats relevés pour arbitrage (aucun fix appliqué)

**1. `leftBar.popoverItem` — valeur fantôme du piège 1-caractère.**
Dark `#070D19` et light `#ECECF2` correspondent **exactement** aux
anciennes valeurs (pré-fix) de `THEME_*_DEFAULT_BACKGROUND` documentées en
§1 de `TOKEN-MAPPING.md` (`#070d19` / `#ececf2`, avant leur passage à
`#070d18` / `#f2f2f3`). Tout indique un recopiage manuel depuis le même
swatch Figma que le fond, à une époque où ce swatch avait ces valeurs
(désormais obsolètes). Recommandation : câbler
`leftBar.popoverItem: THEME_*_DEFAULT_BACKGROUND` (ou le token FDS
correspondant) pour éliminer la valeur fantôme — même schéma que le fix
gradient. Risque faible (élément décoratif, popover du menu latéral),
mais je n'ai pas appliqué le changement : à votre arbitrage.

**2. Doublons de littéraux (purement cosmétique / maintenabilité, zéro
risque fonctionnel) :**
- `palette.gradient.main` (top-level) recopie `EE_COLOR` en dur au lieu de
  référencer la constante.
- `MuiDialog.paper.backgroundColor` (fallback) recopie
  `THEME_*_DIALOG_BACKGROUND` en dur.
- `MuiSelect`/`MuiAutocomplete` (fallback outlined) recopient
  `background.secondary` en dur, 3 fois au total le même littéral.
- `leftBar.text` recopie `THEME_*_DEFAULT_TEXT` (câblé) en dur au lieu de
  référencer la constante.
- `MuiTextField`/`MuiAutocomplete` (label shrink) recopient
  `palette.text.light` en dur.

Aucun de ces 5 points ne change le rendu (les valeurs sont identiques
aujourd'hui) — pur nettoyage optionnel si vous voulez le faire, sinon sans
impact. Contrairement au point 1, il n'y a pas de valeur fantôme/obsolète
ici.

## Conclusion

Le périmètre **couleur** annoncé dans la description de la PR (sections
1-8 de `TOKEN-MAPPING.md`) est câblé à ~95 % (exceptions documentées et
assumées : `severity.none/default`, `designSystem.secondary.light/dark`
en light, `tertiary.blue.500/900`, `designSystem.background.bg1-4`,
`designSystem.border.*`). Le reste du fichier (section 9 ci-dessus —
palette décorative diverse, `components.*` styling, `tag`) est
majoritairement 🔴 en dur et **n'a jamais été annoncé comme dans le
périmètre** : c'est la même dette typo/spacing déjà actée, étendue à
quelques littéraux de couleur décoratifs. Rien de nouveau cassé ; un seul
constat mérite votre arbitrage (leftBar.popoverItem, point 1 ci-dessus).
