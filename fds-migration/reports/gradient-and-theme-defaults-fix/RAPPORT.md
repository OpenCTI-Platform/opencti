# Fix — gradient de fond + defaults thèmes système (dark/light)

> **Captures et dumps JSON non committés** (hygiène repo : zéro binaire en
> historique git). Screenshots + `before.json`/`after.json` vivent localement
> dans `.fds-validation-artifacts/gradient-and-theme-defaults-fix/`
> (gitignored). Ce document reste la trace durable des valeurs et du verdict.

**Suite de** `fds-migration/reports/custom-theme-investigation/RAPPORT.md`
(anatomie de la feature thèmes + verdict non-cassé). Ce rapport couvre
l'implémentation arbitrée : câblage du gradient, seed backend, mutation DB
locale, validation.

**Commits sur `fds/tokens-colors`** (PR #17115, non mergée — hash rewrités
suite à la purge d'artefacts du 2026-07-12, contenu identique) :
1. `842337c570` — `fix(fds): wire body gradient end-color to FDS layer-0-gradient token`
2. `82f8468c66` — `fix(fds): align built-in theme seed defaults with FDS-wired frontend constants`

---

## 1. Câblage gradient (frontend)

`THEME_DARK_DEFAULT_BODY_END_GRADIENT`/`THEME_LIGHT_DEFAULT_BODY_END_GRADIENT`
(`ThemeDark.ts`/`ThemeLight.ts`) reliés au pont FDS, même schéma que les
autres constantes :

```diff
- const THEME_DARK_DEFAULT_BODY_END_GRADIENT = '#08101D';
+ const THEME_DARK_DEFAULT_BODY_END_GRADIENT = FDS.colors.dark['--color-elevation-background-layer-0-gradient'];
```

`getAppBodyGradientEndColor`'s branche `lighten(background, 0.05)` (seule
mécanique de dégradé pour un thème **custom**) : **non touchée**, confirmé par
la vérification de non-régression (§4).

`TOKEN-MAPPING.md` mis à jour : sign-off explicite sur le flag
`gradient.background`, décision documentée (dead code du champ
`palette.gradient.*` clarifié, vraie cause root-cause + fix identifiés).

## 2. Seed backend

`theme-constants.ts` (`DARK_DEFAULTS`/`LIGHT_DEFAULTS`, consommé par
`initDefaultTheme` sur un environnement neuf) resynchronisé sur les mêmes
valeurs que les constantes frontend — un environnement qui boote pour la
première fois aura désormais des thèmes `built_in` FDS-corrects dès la
création, sans mutation manuelle a posteriori.

## 3. Mutation DB locale — procédure exacte

**Contexte** : cet environnement de dev existait déjà avant le câblage FDS ;
ses 2 rows `Theme` (`built_in: true`) ont été créées avant le fix et
retiennent les anciennes valeurs. Cette procédure les aligne. **C'est le
mode d'emploi à rejouer sur tout environnement pré-existant** lors du
déploiement coordonné (un environnement flambant neuf n'en a pas besoin,
`initDefaultTheme` avec les seeds corrigés §2 suffit).

### 3.1 Ciblage : `built_in: true` uniquement

```graphql
query {
  themes(first: 20) {
    edges { node { id name built_in theme_background theme_paper theme_nav
                   theme_primary theme_secondary theme_accent theme_text_color } }
  }
}
```

Filtrer les résultats sur `built_in: true` (2 rows attendues : `Dark`,
`Light`). **Ne jamais patcher une row `built_in: false`** — c'est un thème
custom d'un utilisateur. `built_in` est fiable : jamais envoyé par la
mutation front de création (`themeAdd`), donc jamais `true` pour un thème
utilisateur.

Sur cet environnement : `Dark` = `c3aa48e2-85ea-445f-bd5e-f11a519000cb`,
`Light` = `b62de4de-a574-4509-9992-af85fbde819e` (dump complet avant/après :
`.fds-validation-artifacts/gradient-and-theme-defaults-fix/db-mutation-dump/before.json` / `after.json`, local-only).

### 3.2 Mutation (une par thème, seulement les champs qui changent)

```graphql
mutation ThemeFieldPatch($id: ID!, $input: [EditInput!]!) {
  themeFieldPatch(id: $id, input: $input) {
    id name theme_background theme_paper theme_nav
    theme_primary theme_secondary theme_accent theme_text_color
  }
}
```

Variables **Dark** (id `c3aa48e2-85ea-445f-bd5e-f11a519000cb`) :
```json
{
  "input": [
    { "key": "theme_background", "value": ["#070d18"] },
    { "key": "theme_paper", "value": ["#0d172b"] },
    { "key": "theme_nav", "value": ["#070d18"] },
    { "key": "theme_secondary", "value": ["#00f0bc"] },
    { "key": "theme_accent", "value": ["#1f3965"] },
    { "key": "theme_text_color", "value": ["#f2f2f3"] }
  ]
}
```
(`theme_primary` omis : `#0fbcff` inchangé.)

Variables **Light** (id `b62de4de-a574-4509-9992-af85fbde819e`) :
```json
{
  "input": [
    { "key": "theme_background", "value": ["#f2f2f3"] },
    { "key": "theme_nav", "value": ["#f2f2f3"] },
    { "key": "theme_secondary", "value": ["#00f0bc"] },
    { "key": "theme_accent", "value": ["#e4e5e7"] },
    { "key": "theme_text_color", "value": ["#18191b"] }
  ]
}
```
(`theme_paper`, `theme_primary` omis : déjà corrects.)

**Le piège `theme_background`** (rapport d'investigation §3.c-iii) : la
valeur cible n'est pas juste "plus proche du token FDS", c'est **exactement**
`#070d18`/`#f2f2f3` — la précédente valeur DB (`#070d19`/`#ececf2`) était
à 1 caractère du défaut FDS, ce qui suffisait à faire prendre à
`getAppBodyGradientEndColor` la branche `lighten()` plutôt que la
constante corrigée. Sans ce détail, le fix §1 seul n'aurait rien changé
visuellement pour ces 2 thèmes.

### 3.3 Exécution utilisée ici (référence, pas obligatoire de la rejouer telle quelle)

Authentification (obtient un cookie de session, pas de token littéral en
retour — normal, l'auth OpenCTI est cookie-based) :
```bash
curl -c cookies.txt -X POST http://localhost:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation($input: UserLoginInput!) { token(input: $input) }",
       "variables":{"input":{"email":"<admin>","password":"<password>"}}}'
```
Puis les 2 mutations `themeFieldPatch` ci-dessus, avec `-b cookies.txt`.

### 3.4 Vérification post-mutation

Re-`query { themes }` : confirmé seulement 2 rows retournées (`Dark`,
`Light`), toutes deux avec les nouvelles valeurs, aucune autre row présente
— aucun thème custom sur cet environnement au moment de la mutation (le
thème de test de l'investigation précédente, « QA Gradient Test », avait
déjà été supprimé en fin d'investigation).

## 4. Validation visuelle post-fix (1+2+3 appliqués)

Captures dans `.fds-validation-artifacts/gradient-and-theme-defaults-fix/validation-screenshots/` (local-only).

| Test | Résultat mesuré (`getComputedStyle`) | Capture |
|---|---|---|
| Thème système **Dark** | `linear-gradient(100deg, rgb(7,13,24) 0%, rgb(12,21,39) 100%)` = **`#070d18 → #0c1527`, exactement le token FDS** | `01-dashboard-dark-after-fix.png` |
| Thème système **Light** | `linear-gradient(100deg, rgb(242,242,243) 0%, rgb(255,255,255) 100%)` = **`#f2f2f3 → #ffffff`, exactement le token FDS** | `02-dashboard-light-after-fix.png` |
| Non-régression : nouveau thème custom (`theme_background=#2a1a4a`, mêmes valeurs que le test de l'investigation précédente) | `linear-gradient(100deg, rgb(42,26,74) 0%, rgb(52,37,83) 100%)` — **identique au bit près** à la mesure d'avant-fix | `03`–`06` (création → application → rendu) |
| Cleanup | thème de test supprimé, préférence perso revenue à Dark, liste finale = Light + Dark uniquement | `07-final-cleanup-theme-list.png` |

**Conclusion : les deux thèmes système rendent maintenant le vrai two-stop
gradient FDS voulu, au pixel près. Le mécanisme `lighten()` des thèmes
custom est prouvé bit-identique avant/après — aucune régression.**

---

*DB locale mutée, code committé + poussé sur `fds/tokens-colors` (PR #17115,
non mergée, non mergeable sans validation). Rien touché sur `master`.*
