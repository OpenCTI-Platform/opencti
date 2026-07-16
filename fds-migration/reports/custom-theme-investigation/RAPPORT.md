# Investigation — Feature « Thèmes custom » vs câblage FDS

> **Captures non committées** (hygiène repo : zéro image en historique git).
> Les 10 screenshots référencés ci-dessous vivent localement dans
> `.fds-validation-artifacts/custom-theme-investigation/` (gitignored). Ce
> document reste la trace durable du parcours et de son verdict.

**Type :** investigation en lecture seule, aucun fix appliqué (code, DB, ou schéma
intouchés). Captures d'écran et requêtes GraphQL uniquement.
**Testé sur :** environnement de dev local (front `:3000`, graphql `:4000`), code
servi = tip de `fds/tokens-colors` / ex-`design-system/current` (commit
`961a4e2345`), donc **le câblage du pilote tel qu'il est dans la PR #17115**.
**Compte de test :** `admin@opencti.io` (identifiants de `development.json`,
lus une seule fois sur autorisation explicite).

---

## 1. Anatomie de la feature

### 1.a Le modèle

Les thèmes sont des **entités DB à part entière** (type interne `Theme`,
`opencti-graphql/src/modules/theme/theme.graphql`), pas une simple config.
Champs :

| Champ | Obligatoire | Rôle |
|---|---|---|
| `name` | oui | libellé affiché dans les listes/select |
| `theme_background`, `theme_paper`, `theme_nav`, `theme_primary`, `theme_secondary`, `theme_accent`, `theme_text_color` | oui, `String!` | les **7 couleurs** que l'utilisateur peut personnaliser |
| `theme_logo`, `theme_logo_collapsed`, `theme_logo_login` | non | logos custom |
| `theme_login_aside_color/gradient_start/gradient_end/image` + un sélecteur de type (couleur/dégradé/image) | non | habillage du panneau de login — **seul endroit où un vrai dégradé 2 couleurs est saisissable par l'utilisateur** |
| `built_in` | `Boolean` | **le flag qui distingue les thèmes système des thèmes custom** |

**Distinction thème par défaut vs thème custom : `built_in`, un booléen, rien
d'autre.** Pas de nom réservé, pas d'ID magique, pas de seed séparé côté
schéma — juste ce flag. Les deux thèmes livrés (« Light », « Dark ») ont
`built_in: true`, posé une fois par `initDefaultTheme` au bootstrap de la
plateforme. **Tout thème créé depuis l'UI a `built_in: false`** : la mutation
front (`themeAdd`) n'envoie jamais ce champ, donc impossible pour un
utilisateur de se fabriquer un thème qui se fasse passer pour un thème système.

Point de vigilance (déjà noté au rapport gradient précédent, reconfirmé ici) :
`fieldPatchTheme` (l'édition) n'a **aucun garde-fou sur `built_in`** — un thème
système est éditable comme un thème custom. C'est ce qui permet le fix DB
proposé plus bas (patcher les rows `built_in: true` directement), mais ça
signifie aussi qu'il n'y a **aucune protection technique empêchant un admin de
casser accidentellement Light/Dark** — c'est juste que l'UI ne le pousse pas à
le faire aujourd'hui.

### 1.b Le cycle de vie

**Création** (`ThemeCreation.tsx`, drawer « + » dans Settings → Configuration →
Thèmes) : formulaire **entièrement vierge** — tous les champs couleur partent
de `''`, aucun pré-remplissage depuis les constantes FDS ni depuis le thème
actif. Confirmé en code et en live (capture `01-create-drawer-blank.png`).
**Aucun champ dégradé pour le fond principal** — seul le panneau login a
l'option dégradé. Mutation `themeAdd(input: ThemeAddInput!)`.

**Édition** (`ThemeEdition.tsx`, clic sur un thème existant) : même formulaire,
pré-rempli cette fois avec les valeurs actuelles du thème. Mutation
`themeFieldPatch`, un champ à la fois.

**Application** — **deux couches indépendantes**, toutes deux vérifiées en
live :
1. **Réglage plateforme** : `settings.platform_theme` (Settings →
   Configuration → « Thème par défaut »), s'applique à tout utilisateur sans
   préférence personnelle. Sur cette instance : `Light`.
2. **Préférence personnelle** : `me.theme` (Profil → « Expérience Utilisateur »
   → « Thème »), prioritaire sur le réglage plateforme. Sur ce compte admin :
   `Dark` — d'où le rendu sombre malgré `platform_theme = Light`.

`useActiveTheme(userThemeId, platformTheme, allThemes)` résout la couche
effective : `userThemeId` (sauf sentinelle `'default'`/absent) prioritaire,
sinon `platformTheme`. Si le thème pointé a été supprimé entretemps,
`ThemePopover` recale la préférence utilisateur sur le thème par défaut via
`meEdit`.

### 1.c Le rendu — quel est le rôle exact du code vs de la DB ?

Chaîne confirmée (code + fetch HTTP live du serveur Vite + navigateur réel) :

```
RootPrivateQuery (me.theme, settings.platform_theme, themes{...})
  → useActiveTheme(...)                                     // résout la couche effective
  → AppThemeProvider :
       themeToUse = exportTheme ?? activeTheme ?? settings.platform_theme
       appTheme.theme_X = themeToUse?.theme_X ?? defaultTheme.theme_X   // defaultTheme = constantes FDS
  → themeBuilder(appTheme) → themeDark(...)/themeLight(...)
       chaque paramètre : param || THEME_DARK_DEFAULT_X                  // fallback si '' ou null
  → MuiCssBaseline.body.background =
       linear-gradient(100deg, background||DEFAULT 0%, getAppBodyGradientEndColor(background) 100%)
```

**Réponse directe à la question posée : la DB est la source de vérité dès
qu'un thème existe. Le code (constantes FDS) ne sert que de secours de
dernier recours**, dans exactement 3 cas, jamais plus :
- un champ DB est `null`/absent sur un theme row (`?? defaultTheme.theme_X`) ;
- un champ résolu est une chaîne vide `''` (`|| THEME_DARK_DEFAULT_X`) — en
  pratique n'arrive jamais via l'UI puisque les 7 champs sont `required` côté
  formulaire ;
- calcul de la 2ᵉ couleur du dégradé de fond quand `background` égale
  *exactement* la valeur par défaut FDS (`getAppBodyGradientEndColor`, voir
  §2.c et §3).

Le code ne fournit **aucun pré-remplissage** à la création d'un thème custom
(vérifié §1.b) et **aucun seed** — le seed des thèmes livrés passe par
`theme-constants.ts` (`DARK_DEFAULTS`/`LIGHT_DEFAULTS`), un fichier **distinct**
des constantes FDS front (`THEME_DARK_DEFAULT_*` dans `ThemeDark.ts`), déjà
signalé au rapport précédent comme non resynchronisé sur les tokens FDS.

---

## 2. État des lieux post-pilote — walkthrough complet

Parcours réalisé intégralement en live (Playwright + Chrome), captures dans
ce dossier :

| # | Étape | Capture |
|---|---|---|
| 1 | Drawer de création, vierge | `01-create-drawer-blank.png` |
| 2 | Drawer rempli (thème test « QA Gradient Test », `theme_background=#2a1a4a`) | `02-create-drawer-filled.png` |
| 3 | Toast de succès + thème listé à côté de Light/Dark | `03-after-create.png` |
| 4 | Thème appliqué en préférence perso (Profil), UI totalement re-thémée | `04-profile-after-apply.png` |
| 5 | Dashboard avec le thème custom appliqué | `05-dashboard-custom-theme-applied.png` |
| 6 | Dashboard, retour sur le thème système « Dark » | `06-dashboard-builtin-dark.png` |
| 7 | Profil après retour à « Dark » | `07-profile-reverted-to-dark.png` |
| 8 | Menu contextuel du thème (Modifier/Exporter/Supprimer) | `08-theme-popover-menu.png` |
| 9 | Dialogue de confirmation de suppression | `09-delete-confirm-dialog.png` |
| 10 | Liste finale : seuls Light/Dark restent | `10-after-delete-theme-list.png` |

### 2.a Valeurs pré-remplies à la création

**Aucune** — confirmé capture `01`. Le formulaire est vide, cohérent avec le
code (§1.b). Pas de régression possible ici : le comportement n'a jamais
dépendu des constantes câblées.

### 2.b Mesure directe du rendu (computed style, pas une impression visuelle)

`getComputedStyle(document.body).backgroundImage` relevé à chaque étape :

| Thème actif | `theme_background` (DB) | Résultat mesuré | Branche de calcul |
|---|---|---|---|
| **QA Gradient Test** (custom) | `#2a1a4a` | `linear-gradient(100deg, rgb(42,26,74) 0%, rgb(52,37,83) 100%)` | `lighten(background, 0.05)` — `background ≠` défaut FDS |
| **Dark** (système) | `#070d19` (stale, pré-FDS) | `linear-gradient(100deg, rgb(7,13,25) 0%, rgb(19,25,36) 100%)` | `lighten(background, 0.05)` — `#070d19 ≠ #070d18` (défaut FDS), d'1 unité hex près |
| **Light** (système) | `#ececf2` (stale, pré-FDS) | `linear-gradient(100deg, rgb(236,236,242) 0%, rgb(236,236,242) 100%)` | `lighten(background, 0.05)` — mais **arrondi 8-bit identique au point de départ** (voir §2.c) |
| **Défaut** (= `platform_theme` = Light) | idem Light | idem Light | idem |

**Conclusion factuelle : la mécanique de dégradé pour un thème CUSTOM
fonctionne aujourd'hui correctement.** `#2a1a4a` → `#341f2553`… pardon,
`rgb(52,37,83)` est bien un `lighten(#2a1a4a, 5%)`, la première teinte est
reprise exactement. Rien n'est cassé sur ce chemin par le câblage du pilote —
le câblage du pilote (le champ mort `palette.gradient.background`, voir
rapport précédent) n'intervient nulle part dans ce calcul.

### 2.c Cas limite demandé — thème custom sans dégradé défini

Réponse : **c'est le cas général**, pas une exception — *aucun* thème,
custom ou système, ne peut définir explicitement la 2ᵉ couleur du dégradé de
fond (§1.a : pas de champ dans le formulaire). Le rendu est **toujours** le
dérivé calculé (`lighten(theme_background, 0.05)`), sauf si
`theme_background` égale *exactement* la constante par défaut FDS, auquel cas
c'est une constante câblée en dur qui est utilisée à la place. C'est
exactement ce que confirme la ligne « Dark » du tableau ci-dessus : la DB
vaut `#070d19`, à 1 unité hex du défaut FDS `#070d18` — assez proche pour
qu'on croie que c'est « la même valeur », mais **juste assez différent** pour
basculer sur la branche `lighten()` plutôt que sur la constante câblée. Ce
point a une conséquence directe sur le fix (§3.c).

**Ce comportement (dérivation par `lighten()` à partir de `background`) est
celui que tout fix futur doit préserver à l'identique** pour les thèmes
custom — c'est la seule mécanique qui existe, il n'y en a pas d'autre à
« restaurer ».

### 2.d Comparaison avec master

Non nécessaire pour trancher : le test live ci-dessus répond directement à
la question (le mécanisme fonctionne), et le mécanisme de calcul
(`getAppBodyGradientEndColor`) est un morceau de code **pré-existant, non
touché par le câblage du pilote** — seule la valeur de `palette.gradient.*`
(dead code, jamais lue par `MuiCssBaseline`) a été ajoutée. Comparer avec
`master` n'aurait rien montré de plus que ce que le live confirme déjà.

### 2.e Bonus — le bug GraphQL `theme`/`themes` (aparté)

Rapport précédent : la query GraphQL `theme`/`themes` crashait
(`elQueryBodyBuilder`). Confirmé de nouveau ici : **ce bug n'affecte pas
l'usage réel** — toute l'UI Thèmes (liste, création, édition, application,
suppression) passe par d'autres chemins (probablement chargement direct par
listage de connexion plutôt que la query nommée testée) et fonctionne
parfaitement de bout en bout, comme démontré par ce walkthrough complet. Le
bug GraphQL reste réel mais isolé — pas un facteur pour l'arbitrage en cours.

---

## 3. Synthèse pour décision

### 3.a La DB est-elle le cœur de la feature, ou un cache/accessoire ?

**Le cœur.** Chaque thème (système ou custom) est une entité DB de premier
rang ; le code ne fournit qu'un filet de sécurité pour des champs
absents/vides, jamais une source primaire une fois qu'un thème existe. Le
seul autre rôle du code est le **seed** initial des thèmes système
(`theme-constants.ts`, distinct des constantes FDS front, déjà signalé comme
désynchronisé).

### 3.b Le pilote a-t-il cassé quelque chose ?

**Verdict : NON pour la feature « thèmes custom » elle-même.** Le parcours
complet (créer → pré-remplissage → éditer/appliquer → rendu → révoquer →
supprimer) fonctionne de bout en bout, y compris le calcul du dégradé de fond
pour une couleur custom, mesuré directement via `getComputedStyle` (pas une
impression visuelle). Le câblage du pilote (`palette.gradient.background`)
est un champ mort qui n'intersecte à aucun moment ce chemin.

Les bugs déjà identifiés (rapport précédent) restent les seuls bugs réels,
et **aucun ne touche les thèmes custom** :
- rows DB des thèmes **système** (Light/Dark) encore sur des hex pré-FDS ;
- constantes de secours `THEME_{DARK,LIGHT}_DEFAULT_BODY_END_GRADIENT`
  câblées en dur avec des valeurs approximatives plutôt que reliées au pont
  FDS (nouveau détail exact ci-dessous, §3.c) ;
- constantes de seed backend (`theme-constants.ts`) non resynchronisées.

### 3.c Recommandations révisées

**i. Critère de ciblage pour le fix DB : `built_in: true`, confirmé fiable et
suffisant.** Ne cible que les 2 rows système (Light/Dark). Aucun thème
custom n'a jamais `built_in: true` (jamais envoyé par la mutation front) —
zéro risque de toucher un thème utilisateur avec ce filtre.

**ii. Nouveau détail exact, qui change l'ordre des opérations du fix
gradient.** En creusant le code exact (`ThemeDark.ts`/`ThemeLight.ts`) :

```ts
export const THEME_DARK_DEFAULT_BACKGROUND = FDS.colors.dark['--color-elevation-background-layer-0'];   // ✅ relié au pont FDS
const THEME_DARK_DEFAULT_BODY_END_GRADIENT = '#08101D';                                                  // ❌ constante en dur, PAS reliée au pont
```

Le pont expose déjà tout ce qu'il faut (`fds-tokens.generated.ts`) :

| | Défaut FDS (`--layer-0`) | Défaut FDS (`--layer-0-gradient`) | Constante câblée aujourd'hui |
|---|---|---|---|
| Dark | `#070d18` | **`#0c1527`** (déjà dans le pont) | `#08101D` (en dur, faux) |
| Light | `#f2f2f3` | **`#ffffff`** (déjà dans le pont) | `#F7F7F7` (en dur, faux) |

Donc **pas besoin de faire évoluer le pont ni la lib** (reconfirmé — la paire
`layer-0`/`layer-0-gradient` existe et est déjà exposée). Le fix est
purement local à `ThemeDark.ts`/`ThemeLight.ts` : remplacer les 2 littéraux
en dur par `FDS.colors.dark['--color-elevation-background-layer-0-gradient']`
et l'équivalent light — exactement le même schéma que
`THEME_DARK_DEFAULT_BACKGROUND` deux lignes au-dessus. Micro-diff, aucun
risque architectural.

**iii. Piège découvert — les deux fixes (DB + constante) sont
interdépendants, il faut les faire ENSEMBLE :**

Row DB `Dark` actuelle = `#070d19`, à **1 unité hex** du défaut FDS `#070d18`.
Cet écart minuscule suffit à faire passer `getAppBodyGradientEndColor` par la
branche `lighten()` plutôt que par la constante de secours — c'est
d'ailleurs pourquoi la mesure live (§2.b) montre `lighten(#070d19)`, pas la
constante `#08101D`. Conséquence :
- Si on corrige **seulement** la row DB (`#070d19` → `#070d18` exact), le
  code bascule sur la constante de secours — qui reste **fausse**
  (`#08101D` au lieu de `#0c1527`) tant qu'elle n'est pas corrigée aussi.
- Si on corrige **seulement** la constante de secours sans toucher la row
  DB, la branche `lighten()` continue de s'exécuter (puisque `#070d19 ≠
  #070d18` persiste) — la constante corrigée ne sera jamais utilisée.

**→ Il faut livrer les deux corrections dans le même changement** pour que le
thème système Dark rende effectivement `#070d18 → #0c1527` (le dégradé
FDS voulu). Idem pour Light (`#ececf2`→`#f2f2f3` exact + constante
`#F7F7F7`→`#ffffff`).

**iv. La colonne B1 (mapping token) reste la bonne approche** — rien dans
l'anatomie de la feature custom-theme ne la remet en cause. Elle doit juste
s'accompagner du point (iii) pour être effective.

**v. Contrainte à respecter dans l'implémentation du fix (rappel) :** ne
jamais toucher `getAppBodyGradientEndColor`'s branche `lighten()`
elle-même — c'est le seul mécanisme qui rend un dégradé de fond pour un
thème custom (§2.c), il n'existe pas de champ pour l'authorer autrement.
Le fix ne doit changer QUE : (a) les 2 rows DB `built_in: true`, (b) les 2
constantes de secours câblées, (c) les constantes de seed backend
(`theme-constants.ts`, signalé rapport précédent). Zéro changement sur la
logique de dérivation elle-même.

---

*Rapport préparé pour arbitrage — aucune correction appliquée. En attente de
validation avant toute implémentation.*
