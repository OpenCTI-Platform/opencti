# Inventaire des écarts — Paper (lib) vs surfaces conteneur OpenCTI

Rendu **avant** toute conversion, comme prérequis bloquant de la vague pilote
Paper. Les sections 0 à 6 sont l'inventaire tel qu'il a été rendu, quand rien
n'était converti — elles ne sont pas réécrites. Les arbitrages de Sandy (§7,
§10), les captures de test du cas laissé ouvert (§8) et les deux lots convertis
(§9 échauffement, §11 pilote) sont ajoutés à la suite.

- Produit : OpenCTI, branche `fds/paper-pilot` sur `design-system/current`
  (base `a45a8342378990c0606518b8c11bc21140cff9cf`).
- Lib : pin `35a476849ba72d48cacae2568643f0b5638bc468` →
  **`a22b188b28bc151f930d19d4f8ed7114df581e6e`** (tête d'`origin/main`),
  qui apporte #121 (renommage de tokens), #122, #123/#124 (navbar) et
  #125 (bordure du Paper à 15 %).
- **Toutes les valeurs ci-dessous sont mesurées sur le DOM rendu**, dans le
  vrai thème MUI du produit (`ThemeDark`/`ThemeLight` appelés comme
  `AppThemeProvider` les appelle, `spacing: 8`), avec la **pile de feuilles
  complète** que `front.tsx` importe — la feuille de la lib, `static/css/index.css`
  et `static/css/design-system-host.css`. Jamais lues dans les types, le
  changelog ou la doc.
- Périmètre mesuré : **les 28 `<Paper>` directs**, un par un.

---

## 0. Étape 0 — le gate, sur le build installé

### 0.1 Pin prouvé par les OCTETS SERVIS

Serveurs arrêtés avant purge (aucun serveur de cette session ne tournait : le
clone est neuf, hors OneDrive, `~/dev/paper-cti`), `node_modules` et le paquet
absents par construction, installation complète, puis relevé **dans le CSS que
le serveur de dev délivre réellement** — pas dans le lockfile :

| forme cherchée dans les octets servis | avant | **après** |
|---|---|---|
| `transparency-40` | présent | **0** |
| `transparency-15` | 0 | **29** |
| `--color-filigran-brand-primary-transparency:` (ancien nom) | déclaré | **0** |
| `--color-filigran-brand-primary-transparency-10:` (nouveau) | 0 | **6** |

Les trois feuilles du produit sont bien chargées (114 874 + 761 618 + 1 141
octets) : la mesure se fait dans la cascade réelle de l'hôte.

### 0.2 Les quatre points du gate

| Point demandé | État | Mesure |
|---|---|---|
| prop `padding`, échelle 0/8/16/24/32 | ✅ | rend `p-0`/`p-2`/`p-4`/`p-6`/`p-8` → **0/8/16/24/32 px mesurés**. Les **cinq** classes existent dans la feuille servie. Défaut 24. Plus aucune fuite en attribut DOM. |
| props `title` / `action` | ✅ **présentes** | rangée d'en-tête au-dessus de la surface, hors bordure et hors padding : `<div class="flex h-6 items-center gap-2 …">`. **Voir G5 : présentes ≠ adoptables ici.** |
| contrat de thème hôte | ✅ | vérifié **dans les deux sens** : redéclarer la **base par couche** (`--bg-elevation-default-layer-1`, `--border-elevation-subtle-soft-layer-1`) repeint surface **et** bordure (`rgb(13,23,43)` → `rgb(59,36,80)`, bordure → `srgb(0.231,0.141,0.314)/0.15`) ; redéclarer l'**alias** (`--bg-elevation-default`, `--border-elevation-subtle-soft`) **ne fait rien**. |
| bordure au token `subtle-soft`, dilution 15 % | ✅ | `border-elevation-subtle-soft` par couche, `…-transparency-15: color-mix(… 15%, transparent)` re-déclaré dans chaque `.layer-N`. Base claire `--gray-400`, base sombre `--grayblue-400`. |

**Verdict étape 0 : GATE VERT.** Les quatre capacités sont là. Rien n'a été
bricolé côté produit pour les obtenir.

### 0.3 Un comportement relevé au passage, non demandé mais structurant

Une valeur **hors échelle** ne rend **aucune** classe de padding — la surface
tombe à **0px**, sans erreur ni avertissement :

| prop | padding mesuré |
|---|---|
| `padding={15}` | **0px** |
| `padding={20}` | **0px** |

C'est LIBRARY-FEEDBACK OpenAEV #32, **toujours ouvert** à ce pin. Il est
nettement plus dangereux ici que là-bas : **15 et 20 sont les deux valeurs les
plus fréquentes d'OpenCTI** (9 des 28 sites), et le produit a `allowJs` sans
`checkJs`, donc `StixDomainObjectAuthorKnowledge.jsx` n'a aucune vérification
de props. Repris en LIBRARY-FEEDBACK OpenCTI #30.

### 0.4 Chasse aux références mortes — 3 trouvées, **les 3 silencieuses**

Le renommage de #121 fait disparaître **17 clés** du pont
(`-transparency` → `-transparency-<N>`). Régénérer le pont
(`pnpm generate:mui-bridge --product opencti`, jamais à la main) ne suffit pas
à les voir : `tsc --noEmit` passe **sans une seule erreur**, eslint aussi, le
build aussi.

Grep de **tout** le code produit (2 593 fichiers, pas seulement les
`wiredFiles`) sur les deux formes, recoupé contre le `dist/index.css`
**installé** :

| # | référence | fichier | signal | conséquence mesurée |
|---|---|---|---|---|
| 1 | `var(--color-filigran-brand-primary-transparency)` **lue** | `TopBarIconLink.tsx:8` | **silencieuse** | `var()` pendant : le fond du lien sélectionné du top bar n'a plus de valeur. `TopBar` et `NavBar` sont **frères** (`private/Index.tsx:122-123`), donc aucune déclaration produit ne le couvrait. |
| 2 | `--color-filigran-brand-primary-transparency` **déclarée** | `NavBar.tsx:101` | **silencieuse** | le Navbar de la lib rend `bg-filigran-brand-primary-transparency-10`, qui lit le **nouveau** nom. Mesuré : rangée sélectionnée peinte `srgb(0.259,0.792,1)` = le **bleu Filigran par défaut** au lieu de l'accent client `#ff8a3d`. La teinte client ne passait plus. |
| 3 | le même littéral, **asserté** | `TopBarIconLink.test.tsx:29` | **silencieuse** | le test compare la chaîne, pas la couleur résolue : il restait **vert** sur une référence morte. |

`-transparency-50` (`NavBar.tsx:102`) **n'a pas été renommé** et reste valide —
vérifié, pas supposé.

**Corrigé** (c'est le bump qui a cassé, la remise en place est strictement ISO) :
les trois références passent au nouveau nom. Re-scan après correction :
**forme A = 0, forme B = 0**.

### 0.5 Le garde-fou d'OpenCTI a fait son travail — et a dû être affiné

`NavBar.test.tsx` porte un garde qui lit le `dist/index.css` **installé**,
extrait toute custom property résolue par les règles `aria-current`, et exige
que le rail les surcharge toutes. Il **est passé au rouge** sur ce bump, sur
`--text-default-primary`.

Ce n'est pas un faux rouge et ce n'est pas non plus le défaut qu'il cherchait :
#123 fait prendre au **glyphe** d'une rangée sélectionnée le ton de texte
primaire ordinaire (`group-[[aria-current=page]]:text-default-primary` sur le
span d'icône de `NavbarItem`) — délibérément **pas** l'accent. Le surcharger
avec `theme_primary` repeindrait une icône que la Figma dit neutre.

Le garde a donc été **resserré sur son intention déclarée**, pas affaibli :
une liste fermée `NOT_ACCENT_DERIVED`, une entrée = une raison, et
l'assertion **inverse** sur les exemptés (un exempté ne doit **pas** être
surchargé) pour que l'exemption ne pourrisse pas en ignore global. Toute
propriété qu'un futur pin introduirait reste rouge par défaut.

### 0.6 Attendu, pas une régression : la couleur warning fonce en clair

Mesuré par mode sur le pont régénéré :

| mode | token | avant | après |
|---|---|---|---|
| clair | `--color-feedback-warning-primary` | `#e6700f` | **`#b8550a`** |
| clair | `--color-feedback-warning-tertiary` | `#884106` | **`#572a05`** |
| sombre | les deux | inchangés | inchangés |

OpenCTI lit `--color-feedback-warning-primary` à **3 endroits par fichier de
thème** (`ThemeLight.ts:50, 130, 202` et les 3 mêmes lignes dans `ThemeDark.ts`),
plus `--color-feedback-warning-secondary` une fois chacun — **8 lectures au
total, dont 3 portent la valeur qui bouge** (celles de `ThemeLight`). Elles
alimentent `palette.warning.main`, le niveau `high` et
`palette.…warning.primary`. `--icon-warning` et `--border-alert-warning`
bougent aussi en clair mais **ne sont lus nulle part** dans le produit.

**Montré, pas corrigé.**

---

## 1. Les 28 sites, relevés un par un

Padding **mesuré au DOM**, dans le thème sombre par défaut (identique en clair
et en thème client — le padding ne dépend pas du thème).

| id | fichier:ligne | famille | padding mesuré | bordure mesurée | ombre |
|---|---|---|---|---|---|
| F1 | `components/CreateSplitControlledDial.tsx:114` | flottant | 0 | **aucune** | élévation MUI |
| F2 | `components/nested_menu/NestedMenuButton.tsx:295` | flottant | 0 | **aucune** | élévation MUI |
| F3 | `…/sub_types/workflow/PublishButton.tsx:140` | flottant | 0 | **aucune** | élévation MUI |
| T1 | `…/common/history/HistoryLineContent.tsx:107` | semi-transparent | `8/15/0/15` | **aucune** | élévation MUI |
| T2 | `…/settings/users/UserHistoryLine.tsx:339` | semi-transparent | `8/15/0/15` | **aucune** | élévation MUI |
| G1 | `…/settings/experience/ExperienceCard.tsx:57` | dégradé | 16 | `rgba(255,255,255,.12)` | none |
| N1 | `…/data/connectors/ConnectorWorksErrorLine.tsx:96` | nu | **15** | `rgba(255,255,255,.12)` | none |
| N2 | `…/data/connectors/ConnectorWorksErrorLine.tsx:122` | nu | **15** | `rgba(255,255,255,.12)` | none |
| N3 | `…/drafts/DraftRoot.tsx:203` | nu | **15** | `rgba(255,255,255,.12)` | none |
| N4 | `…/scale_configuration/ScaleConfiguration.tsx:209` | nu + **titre hors surface** | **15** | `rgba(255,255,255,.12)` | none |
| N5 | `…/common/form/HeaderField.tsx:32` | nu | **20** | `rgba(255,255,255,.12)` | none |
| N6 | `…/common/form/QueryAttributeField.tsx:43` | nu | **20** | `rgba(255,255,255,.12)` | none |
| N7 | `…/StixDomainObjectAuthorKnowledge.jsx:273` | nu + **titre hors surface** | `20/20/0/20` | `rgba(255,255,255,.12)` | none |
| N8 | `…/data/stream/StreamConsumersDrawer.tsx:116` | nu | 16 | `rgba(255,255,255,.12)` | none |
| N9 | `…/entity_setting/EntitySettingCustomOverview.tsx:85` | nu | 0 | **aucune** | élévation MUI |
| N10 | `components/ImageCarousel.tsx:143` | nu | 0 | **aucune** | élévation MUI |
| N11 | `…/import_files/ImportFilesFormSelector.tsx:74` | nu (enfant `List`) | 0 | `rgba(255,255,255,.12)` | none |
| N12 | `…/profile/api_tokens/TokenList.tsx:114` | nu | 0 | `rgba(255,255,255,.12)` | none |
| N13 | `…/settings/users/UserTokenList.tsx:110` | nu | 0 | `rgba(255,255,255,.12)` | none |
| H1-H3 | `…/sso_definitions/AuthProviderGroupsFields.tsx:54, 97, 150` | en-tête **interne** | 0 | `rgba(255,255,255,.12)` | none |
| H4-H6 | `…/sso_definitions/AuthProviderOrganizationsFields.tsx:43, 86, 139` | en-tête **interne** | 0 | `rgba(255,255,255,.12)` | none |
| H7 | `…/sso_definitions/AuthProviderUserInfoFields.tsx:33` | en-tête **interne** | 0 | `rgba(255,255,255,.12)` | none |
| H8 | `…/sso_definitions/HeaderStrategyForm.tsx:316` | en-tête **interne** | 0 | `rgba(255,255,255,.12)` | none |
| H9 | `…/global_workflow_request_access/RequestAccessSettings.tsx:75` | titre **dans** la surface | 16 | `rgba(255,255,255,.12)` | none |

Distribution des paddings : **0 → 15 sites**, **15 → 4**, **16 → 3**,
**20 → 2**, **asymétrique → 3** (`8/15/0/15` ×2, `20/20/0/20` ×1),
soit **9 sites hors de l'échelle de la lib**.

---

## 2. Les écarts, un par un

### G1 — Padding : 9 sites sur 28 ne sont pas exprimables

L'échelle de la lib est **0/8/16/24/32, uniforme**. OpenCTI rend :

| valeur produit | sites | exprimable ? |
|---|---|---|
| 0 | 15 | ✅ `padding={0}` |
| 16 | 3 | ✅ `padding={16}` |
| **15** | 4 (N1, N2, N3, N4) | ❌ pas de pas à 15 ; le plus proche est 16 → **+1px sur les quatre côtés** |
| **20** | 2 (N5, N6) | ❌ pas de pas à 20 ; 16 → −4px, 24 → +4px, **équidistants** |
| **`8/15/0/15`** | 2 (T1, T2) | ❌ **asymétrique** — la prop est uniforme, aucune valeur ne convient |
| **`20/20/0/20`** | 1 (N7) | ❌ **asymétrique** — idem |

**Fréquence : 9/28, soit 32 % du périmètre.** Et l'échappatoire `className="p-[15px]"`
n'existe pas : OpenCTI ne compile pas Tailwind, il consomme la feuille
pré-construite ; une classe inventée ne résout rien. Y réintroduire un padding
en dur est exactement ce que la garde de conformité doit faire rougir.

**Ce que je NE fais pas :** choisir 16 « au plus proche » en silence sur N1-N4.
`+1px` × 4 côtés × 4 sites est un changement de densité réel, non-ISO.

**Planches** : `planche-{dark,light,client}.png`, colonne gauche = produit,
colonne droite = l'après simulé avec le padding qu'une conversion à intention
ISO passerait. N5/N6/N7 y montrent visiblement la surface qui rétrécit.

### G2 — Bordure : le produit est **coupé en deux**, pas uniformément sans bordure

C'est le point qui demandait la mesure, et la mesure corrige la prémisse.
`ThemeDark`/`ThemeLight` ne déclarent **pas** `palette.divider` et
n'overrident `MuiPaper` que sur `color` : MUI applique donc sa bordure
`outlined` par défaut.

| | sites | bordure mesurée |
|---|---|---|
| avec `variant="outlined"` | **21 / 28** | `1px solid rgba(255,255,255,.12)` sombre, `rgba(0,0,0,.12)` clair |
| sans `variant` | **7 / 28** (F1, F2, F3, T1, T2, N9, N10) | **`0px none`** — et une **ombre d'élévation MUI** à la place |

Le Paper de la lib dessine **toujours** une bordure, jamais d'ombre. Donc :

- pour les **21 sites outlined**, l'écart est une **différence de teinte**, pas
  de présence. Contraste bordure/surface mesuré :

  | mode | produit | lib | écart |
  |---|---|---|---|
  | sombre | 1,32:1 | 1,09:1 | lib plus discrète |
  | clair | **1,32:1** | **1,15:1** | lib plus discrète |

- pour les **7 sites non-outlined**, l'écart est **double et structurel** : la
  lib **ajoute** une bordure qui n'existe pas, et **retire** l'ombre
  d'élévation qui existe (`rgba(0,0,0,0.2) 0 2px 1px -1px, …`). Le Paper de la
  lib mesure `box-shadow: none` aux quatre élévations. **Aucune prop ne permet
  de désactiver la bordure ni de porter une ombre.**

**Conséquence** : les 7 sites non-outlined ne sont pas convertibles sans perte
en l'état. Ce n'est pas le même écart que les 21 autres et il ne se tranche pas
de la même façon.

### G3 — Fond : le Paper lib ignore le thème client

OpenCTI laisse l'admin surcharger `theme_paper`. Mesuré avec
`theme_paper: #3b2450` passé par `themeDark()` comme `AppThemeProvider` le fait :

| | fond mesuré |
|---|---|
| produit (MUI Paper) | `rgb(59,36,80)` = **`#3b2450`**, la couleur du client |
| lib `Paper` | `rgb(13,23,43)` = **`#0d172b`**, le défaut Filigran |

Sur les thèmes par défaut les deux sont **identiques au pixel**
(`#0d172b` sombre, `#ffffff` clair) : l'écart n'apparaît qu'avec un thème
client — c'est pourquoi il est mesuré sur un vrai thème client et pas déduit.

**Le contrat existe et fonctionne** (§0.2) : il faut redéclarer la **base par
couche**, pour la surface **et** pour la bordure. Ce n'est pas un écart à
arbitrer mais un **câblage à faire** — voir §3, décision D6.

### G4 — Élévation / ombre : pas d'équivalent pour les 7 sites non-outlined

Les 4 couches de la lib sont bien distinctes et alignées sur le produit :

| couche | sombre | clair |
|---|---|---|
| 0 | `#070d18` | `#f2f2f3` |
| 1 (défaut) | **`#0d172b`** = le `background.paper` d'OpenCTI | **`#ffffff`** = idem |
| 2 | `#13213e` | `#f4f4f6` |
| 3 | `#1f3965` | `#e4e5e7` |

Mais l'élévation de la lib est une **couleur de couche**, pas une ombre. Les 7
sites non-outlined d'OpenCTI portent une **vraie ombre portée** MUI. Voir G2.

### G5 — `title` / `action` : présents, mais **pas ISO** sur OpenCTI

Deux sites ont un titre **hors surface** : N4 et N7, tous deux
`<Typography variant="h4" gutterBottom>`. Mesuré au DOM contre la rangée
`title` de la lib :

| | produit (`h4 gutterBottom`) | lib (rangée `title`) |
|---|---|---|
| hauteur | **15,0 px** | **24,0 px** |
| police | IBM Plex Sans 12px | IBM Plex Sans 12px |
| graisse | **500** | **400** |
| interligne | 14,82 px | 18 px |
| interlettrage | `normal` | 0,09 px |
| couleur | `rgb(242,242,243)` (primaire) | `rgb(175,176,182)` (secondaire) |
| écart titre→surface | **4,2 px** | **8,0 px** |

**Delta vertical : +12,8 px par panneau**, plus un changement de graisse et de
couleur. Conformément au mapping arbitré : **on n'adopte pas** `title`/`action`,
on garde l'en-tête produit et on le signale. Même conclusion que côté OpenAEV,
avec les chiffres d'OpenCTI.

Les **8 autres** panneaux « à en-tête » (H1-H8) ne sont pas du même motif : leur
bandeau de titre est **DANS** la surface (`<Box sx={{ px: 2, py: 1.5,
backgroundColor: 'action.hover' }}>`), clippé au rayon par `overflow: hidden`.
`title`/`action`, qui rend **au-dessus** de la surface et sans fond, ne peut pas
le reproduire du tout — ce n'est pas une question d'ISO typographique.

### G6 — Fond en dégradé : un site (G1)

`ExperienceCard.tsx` peint
`linear-gradient(135deg, alpha(accent, .08), transparent 60%)` et le shorthand
`background` **annule le fond du Paper** (mesuré : `rgba(0,0,0,0)`, dans les
trois thèmes). C'est la forme exacte du `DetailHero` d'OpenAEV, tranché là-bas
en **composant à part**. Le Paper lib peint un fond opaque et n'expose ni
dégradé ni transparence.

### G7 — Rayon, `box-sizing`, couleur de texte : **aucun écart**

| propriété | produit | lib |
|---|---|---|
| rayon | 4px | 4px (`rounded-sm`) |
| `box-sizing` | `border-box` | `border-box` |
| ombre (sites outlined) | `none` | `none` |

Aucun écart d'état non plus : ces surfaces sont non-interactives, ni le produit
ni la lib ne rendent de survol, focus ou actif dessus.

---

## 3. Récapitulatif pour arbitrage — 7 décisions

| # | écart | sites | fréquence | produit | lib | ce que je propose |
|---|---|---|---|---|---|---|
| **D1** | padding **15** inexprimable | N1, N2, N3, N4 | 4/28 | 15px | 16px le plus proche | **ne pas convertir** tant que 15 n'est pas exprimable — ou accepter +1px et le dire |
| **D2** | padding **20** inexprimable | N5, N6 | 2/28 | 20px | 16 ou 24, équidistants | **ne pas convertir** — aucun « plus proche » ne s'impose |
| **D3** | padding **asymétrique** | T1, T2, N7 | 3/28 | `8/15/0/15`, `20/20/0/20` | prop uniforme | **ne pas convertir** — inexprimable par construction |
| **D4** | **ombre + absence de bordure** | F1, F2, F3, T1, T2, N9, N10 | 7/28 | pas de bordure, ombre MUI | bordure toujours, ombre jamais | **ne pas convertir** — double perte. F1-F3 relèvent de toute façon de Dialog/Menu (hors périmètre déjà tranché) |
| **D5** | **teinte** de bordure sur les sites outlined | 21/28 | 21/28 | 1,32:1 | 1,09 sombre / 1,15 clair | **acceptable** : la bordure reste présente et perceptible ; c'est la teinte lib assumée par #125 |
| **D6** | **thème client** | tous | 28/28 | suit `theme_paper` | défaut Filigran | **câbler le contrat** : redéclarer la base par couche, surface **et** bordure. Conséquence assumée : plus d'arête visible en thème client — à montrer |
| **D7** | **dégradé d'accent** | G1 | 1/28 | dégradé + fond transparent | fond opaque | **hors périmètre**, comme `DetailHero` côté OpenAEV |

**STOP — j'attends ton arbitrage écart par écart avant toute conversion.**

---

## 4. Périmètre proposé — à valider avant de convertir

Le brief annonçait 14 swap mécanique / 10 adaptation locale / 4 hors périmètre.
**Ma mesure ne retrouve pas ce découpage**, et je le dis plutôt que de le
forcer :

| catégorie | ma mesure | sites |
|---|---|---|
| **swap réellement mécanique** (padding sur l'échelle, bordure déjà dessinée) | **15** | N8, N11, N12, N13, H1-H9 (12) + G1 si le dégradé était réglé |
| **bloqués par un écart non tranché** | **9** | N1-N7 (padding), T1-T2 (padding + ombre + semi-transparence) |
| **hors périmètre déjà tranché** | **4** | F1, F2, F3 (surfaces flottantes Dialog/Menu), G1 (dégradé) |

Les 15 « mécaniques » se répartissent ainsi : **12 sont à padding 0** (les huit
en-têtes SSO H1-H8, plus N11/N12/N13 dont la gouttière vit dans l'enfant) et
**3 sont à 16** (N8, H9, et G1 hors périmètre).

Note : la mesure ne trouve **aucun** `Card.tsx` wrapper ni accordéon parmi les
28 `<Paper>` directs — ces exclusions portent sur d'autres symboles et ne
retirent rien à ce décompte.

### Lot d'échauffement proposé — les 8 en-têtes SSO (H1-H8)

Un seul motif, répété 8 fois, dans 4 fichiers voisins
(`settings/sso_definitions/`), **tous à padding 0** et tous
`variant="outlined"` : la conversion est `padding={0}`, rien d'autre. Aucun
écart de G1/G2 ne les touche. C'est le lot le plus sûr pour valider la chaîne
de bout en bout (garde de conformité comprise) sans mettre un écart en jeu.

Point à trancher dans ce lot : le bandeau de titre interne
(`Box px:2 py:1.5 backgroundColor:'action.hover'`) est un **enfant**, pas un
padding du Paper. Il **reste tel quel** — la règle « le padding des enfants est
retiré » ne s'applique pas, ce padding porte un sens (le bandeau doit toucher
les bords et être clippé par `overflow:hidden`).

### Lot pilote proposé — les 4 restants sans écart (N8, N11, N12, N13, H9)

5 sites, 5 fichiers différents, deux paddings (0 et 16), qui exercent le cas
« la gouttière vit dans l'enfant » (N11 : `<List>` avec séparateurs pleine
largeur — **à ne pas retirer**) et le cas « padding sur la balise » (N8, H9).

**J'attends ta validation du découpage avant de convertir quoi que ce soit.**

---

## 5. Paddings enfants — les sites concernés par la règle « pas de doublement »

| cas | sites | ce que je propose |
|---|---|---|
| le padding vit dans l'**enfant**, le Paper est à 0 | N11 (`List`), N12, N13 (`div.empty`), H1-H8 (bandeau + corps) | **ne rien transférer** : dans les 12 cas la gouttière porte un sens (séparateurs et bandeaux qui doivent toucher les bords). `padding={0}` et on n'y touche pas. |
| padding sur la **balise**, enfant sans padding | N1-N8, H9, G1 | transfert direct au Paper, rien à retirer côté enfant |
| **doublement déjà présent** | **aucun** | rien à reproduire |

Aucun cas de double padding fautif à reproduire à l'identique dans ce
périmètre — la question ne se pose pas ici.

---

## 6. Ce qui reste à faire après ton arbitrage

- la page de login et les écrans publics (élévation des surfaces) — non mesurés
  à ce stade, ils demandent l'app tournante avec son backend ;
- le câblage du thème client (D6) ;
- le motif Paper dans `check-fds-conformity.mjs` avec la garde
  « padding en dur sur un Paper lib » ;
- le checkpoint navbar (cinq états, deux niveaux) sur l'app réelle.

---

## 7. Arbitrages Sandy — 2026-08-16

Appliqués tels quels, sans les rejouer.

| # | décision | portée |
|---|---|---|
| **D1** | padding **15 → 16** (valeur la plus proche de l'échelle) | N1, N2, N3, N4 |
| **D2** | padding **20 → 24** — « entre resserrer et donner un peu d'air, je préfère l'air » | N5, N6 |
| **règle** | aucune conversion « au plus proche » **silencieuse** ailleurs : sans plus proche évident, on remonte | tout le périmètre |
| **D3** | **non tranché** — captures de test demandées, voir §8 | T1, T2, N7 |
| **D5** | bordure : **on garde exactement ce que fait la lib**. Les 21 sites outlined prennent sa teinte ; les 7 sans bordure en **gagnent** une et **perdent** leur ombre MUI. Changement visuel **voulu**, la lib fait référence. | 28/28 |
| **découpage** | **validé** : échauffement = les 8 en-têtes SSO ; pilote = N8, N11, N12, N13, H9 | — |
| **en attente** | teinte, câblage thème client, `title`/`action` non-ISO, dégradé `ExperienceCard`, bandeau dans la surface | rien qui en dépende n'est converti |

### D1/D2 appliqués — le tableau des paddings après règle

| valeur produit | sites | après règle | écart annoncé |
|---|---|---|---|
| 0 | 15 | `padding={0}` | ISO |
| 15 | 4 | `padding={16}` | **+1px** sur les quatre côtés |
| 16 | 3 | `padding={16}` | ISO |
| 20 | 2 | `padding={24}` | **+4px** sur les quatre côtés |
| asymétrique | 3 | — | §8 |

---

## 8. Padding asymétrique — les deux options, mesurées

Trois sites. Mesures au DOM, thème sombre (identiques en clair et en thème
client, le padding ne dépend pas du thème). Hauteur de la surface à contenu
constant :

| site | produit | (a) uniforme | (b) par côté |
|---|---|---|---|
| **T1** `8/15/0/15` | h = **24** | `padding={8}` → h = **32** (+8) · `padding={16}` → h = **48** (**+24, le double**) | `8/16/0/16` → h = **24** — **identique** |
| **T2** `8/15/0/15` | h = **24** | idem T1 | `8/16/0/16` → h = **24** — **identique** |
| **N7** `20/20/0/20` | h = **36** | `padding={24}` → h = **64** (**+28**) | `24/24/0/24` → h = **40** (+4, la seule conséquence de la règle 20→24) |

**Pourquoi T1 et T2 ont deux colonnes (a).** La règle « la valeur la plus
proche » désigne 16 pour l'horizontal (15→16), mais le haut est déjà à 8 et le
bas à 0 : une valeur **uniforme** doit en choisir **une seule**, et 8 comme 16
sont défendables. C'est le cas « pas de plus proche évident » — les deux sont
donc montrées plutôt qu'arbitrées en silence.

**Ce qu'on perd concrètement avec (a).** Sur T1/T2, un bloc de 24px devient
32 ou 48 : ce sont des **lignes d'historique**, empilées par dizaines. À 48, la
liste double de hauteur. Le `0` en bas n'est pas une coquette : il évite de
doubler la gouttière entre deux lignes consécutives. Sur N7, +28px sous un
graphe de 300px de haut.

### Option (b) — ce qu'elle coûterait côté lib

Chiffré, pas estimé. **Rien n'a été poussé côté lib** : la colonne (b) des
captures est une maquette locale qui rend la liste de classes exacte du Paper
installé, padding en moins.

**Forme d'API.** L'ajout naturel est d'élargir la prop existante, pas d'en
ajouter une :

```tsx
padding?: Pad | { block?: Pad; inline?: Pad }        // le cas courant
padding?: Pad | { top?: Pad; right?: Pad; bottom?: Pad; left?: Pad }
```

avec `Pad = 0 | 8 | 16 | 24 | 32` — **l'échelle ne bouge pas**. Les trois sites
d'OpenCTI tombent tous dans la forme longue (`bottom` différent des trois
autres), donc la forme courte `{ block, inline }` ne suffirait pas.

**Effet sur l'échelle existante : aucun.** `padding={16}` continue de rendre
`p-4`. C'est purement additif et non cassant — le nombre reste le raccourci du
cas uniforme.

**Effet sur la feuille livrée : c'est là qu'est le coût réel.** `cva` ne sait
pas exprimer un quadruplet en une variante : il faut **quatre variantes**
(`paddingTop/Right/Bottom/Left`) mappées sur des classes statiques
`pt-/pr-/pb-/pl-`, soit **20 classes**. Mesuré sur le `dist/index.css`
installé, **8 des 20 existent**, par hasard, parce qu'un composant de la lib
les utilise :

| | 0 | 8 | 16 | 24 | 32 |
|---|---|---|---|---|---|
| `pt-` | ❌ | ❌ | ✅ | ❌ | ❌ |
| `pr-` | ❌ | ✅ | ✅ | ❌ | ✅ |
| `pb-` | ❌ | ✅ | ❌ | ❌ | ❌ |
| `pl-` | ❌ | ❌ | ✅ | ✅ | ✅ |

Les 12 manquantes doivent être safelistées dans `src/tokens/index.css`, et
`paper-padding-emission.test.ts` doit prouver que les 20 compilent — exactement
ce que #125 a fait pour `p-8`. C'est le vrai poste de coût, et il est
mécanique, pas conceptuel. Repris en LIBRARY-FEEDBACK #36.

**Effet sur la garde anti-padding-en-dur : elle y gagne.** La garde rougit
quand un padding réapparaît en `className`/`sx`/`style` sur un Paper de la lib.
Aujourd'hui, un site asymétrique ne peut s'exprimer **que** comme ça — donc
soit il reste sur MUI, soit la garde reçoit trois exemptions permanentes. Avec
(b), le padding reste **dans la prop** et la garde reste intègre sur les trois
sites. L'option (b) protège le gate ; la refuser lui coûte trois trous.

**Le risque à connaître.** Une valeur hors échelle rend toujours 0px en silence
(LIBRARY-FEEDBACK #30). Par côté, ce piège est multiplié par quatre. Si (b)
part, l'avertissement dev de #30 devrait partir avec — c'est la même ligne de
code, et elle vaut plus que la fonctionnalité.

---

## 9. Lot d'échauffement — converti, ISO vérifié au DOM

**8 surfaces, 4 fichiers**, tous à `padding={0}` :
`AuthProviderGroupsFields.tsx` (3), `AuthProviderOrganizationsFields.tsx` (3),
`AuthProviderUserInfoFields.tsx` (1, `mt` 20px), `HeaderStrategyForm.tsx` (1).

Aucun des quatre fichiers n'est **mixte** : chacun n'importait le Paper de MUI
que pour ces sites-là, donc les deux gardes sont armées partout.

**Mesuré au DOM, avant vs après, bandeau interne compris :**

| propriété | avant | après |
|---|---|---|
| padding surface | `0/0/0/0` | `0/0/0/0` |
| margin-top | 16px / 20px | 16px / 20px |
| rayon | 4px | 4px |
| `overflow` | `hidden` | `hidden` |
| fond | `rgb(13,23,43)` | `rgb(13,23,43)` |
| largeur × hauteur | 561 × 60 | 561 × 60 |
| **bandeau interne** | pad `12/16/12/16`, fond `rgba(255,255,255,.08)`, 559 × 44 | **identique, aucun écart** |
| bordure | `rgba(255,255,255,.12)` | `srgb(.169,.310,.553)/.15` |

**Le seul écart est la teinte de bordure** — décision D5, voulue.

Le bandeau de titre interne est un **enfant** : son padding n'a pas été
transféré au Paper. Il porte un sens (il doit toucher les bords et être clippé
au rayon par `overflow: hidden`), c'est le cas prévu par la règle.

### Deux capacités absentes de la feuille livrée

`mt-4` et `mt-5` **n'existent pas** dans `dist/index.css` (`overflow-hidden`,
si). La marge est donc posée en `style`, marquée `FDS-WORKAROUND #36` dans les
quatre fichiers. C'est une marge, pas un padding : la garde ne rougit pas, et
c'est correct.

### La garde a été vue rouge avant d'être crue verte

Trois essais, remis en état après chacun :

| essai | verdict |
|---|---|
| `className="… p-4"` sur un Paper lib | ❌ rouge — 3 balises signalées |
| `style={{ padding: 15 }}` sur un Paper lib | ❌ rouge — 3 balises signalées |
| retour au `import Paper from '@mui/material/Paper'` (**l'esquive** que la regex naïve rate) | ❌ rouge — « deep default import » nommé |

Puis vert de nouveau. Le motif `paperPattern` sait aussi déclarer un fichier
**mixte** (`mixed.allowMuiPaperFor` + raison) : aucun site n'en a besoin dans ce
lot, mais la forme existe pour les suivants, plutôt que d'esquiver la regex.

---

## 10. Arbitrages Sandy — 2026-08-16, deuxième tour

| # | décision |
|---|---|
| teinte de bordure | **tranchée** au §7 (D5), la liste des « cinq restants » était périmée sur ce point |
| **bandeau dans la surface** | **reste tel quel** — c'est du contenu produit dans la surface, pas un motif que le Paper doit exprimer. Documenté ci-dessous comme motif non exprimé par la lib, **sans exemption de gate**. |
| padding asymétrique | **option (b)** retenue : prop élargie côté lib. Deux conditions : les 20 classes statiques safelistées et couvertes par le test d'émission, et l'avertissement dev hors échelle **dans la même PR**. En attendant, T1/T2/N7 **ne sont pas convertis**. |
| lot pilote | **lancé** — N8, N11, N12, N13, H9 |

### Le bandeau dans la surface — motif non exprimé par la lib

8 sites (`sso_definitions/*`) rendent, comme **premier enfant** du Paper, un
`<Box sx={{ px: 2, py: 1.5, backgroundColor: 'action.hover' }}>` que
`overflow: hidden` clippe au rayon de la surface.

`title` rend **au-dessus** de la surface, hors bordure, sans fond : il ne peut
pas exprimer ce motif, à aucune typographie. **Décision Sandy : le bandeau reste
un enfant produit.** Ce n'est donc pas un écart à combler côté lib, et **aucune
exemption de gate n'est posée** — les deux gardes restent armées sur les huit
fichiers, parce que le bandeau n'est ni un import MUI ni un padding sur le
Paper. Mesuré identique avant/après (pad `12/16/12/16`, fond
`rgba(255,255,255,.08)`, 559 × 44).

---

## 11. Lot pilote — converti, ISO vérifié au DOM

**5 surfaces, 5 fichiers.** Chacun n'avait qu'un seul `<Paper>` : aucun fichier
mixte, les deux gardes sont armées partout.

| site | avant | après |
|---|---|---|
| **N8** `StreamConsumersDrawer.tsx:116` | `sx` flex + `padding: theme.spacing(2)` + `height: 100%`, `.paper-for-grid` | `padding={16}`, classes flex, **hauteur en style inline** (voir ci-dessous) |
| **N11** `ImportFilesFormSelector.tsx:74` | `sx={{ flex: 1, overflow: 'auto' }}` | `padding={0}`, `className="flex-1"`, `overflow` en style |
| **N12** `TokenList.tsx:114` | `variant="outlined"` | `padding={0}` |
| **N13** `UserTokenList.tsx:110` | `variant="outlined"` | `padding={0}` |
| **H9** `RequestAccessSettings.tsx:75` | `style={paperStyle}` (mt 8, padding 16, rayon 4, relative) | `padding={16}`, `paperStyle` réduit à mt + relative |

**Mesuré au DOM, 15 propriétés par site** (padding, marge, rayon, `overflow`,
`display`, `flex-direction`, `align-items`, `justify-content`, `position`,
`flex`, hauteur calculée, hauteur rendue, largeur, fond, ombre) :

> **écarts hors teinte de bordure : 0 sur les 5 sites.**

La teinte de bordure change partout — décision D5.

**N11 :** le `<List>` garde sa gouttière, rien n'est transféré au Paper. Les
séparateurs continuent de toucher les bords.

**H9 :** le rayon sort de `paperStyle` — `theme.spacing(0.5)` vaut 4px, soit
exactement le `rounded-sm` de la lib, mesuré identique. Le padding sort aussi,
sinon la garde rougirait — à juste titre.

### N8 — le seul site où la conversion naïve n'était PAS ISO

`h-full` **perd** contre `.paper-for-grid` du produit (`height: calc(100% - 25px)`).
Mesuré : 110px attendus, **85px rendus**. Cause : l'utilitaire de la lib vit
dans `@layer utilities`, la classe produit est **non-layerée**, et le non-layeré
gagne — c'est LIBRARY-FEEDBACK #16, qui vient de mordre pour de vrai.

La hauteur repasse donc en `style` inline, qui bat les deux : mesuré 110 → 110.
Marqué `FDS-WORKAROUND #16` sur place. Les classes de flex, elles, n'ont aucun
concurrent non-layeré sur cet élément et s'appliquent normalement.

### Le banc était sous-spécifié, et ça a failli produire un faux résultat

Première mesure de N8 et H9 : `h 144 → 85` et `119 → 85`. Les deux étaient
faux. Le banc ne rendait pas `<CssBaseline />`, que `private/Index.tsx` rend :
sans lui, le Paper de MUI est en `content-box` et celui de la lib en
`border-box`, donc la même hauteur donnait deux boîtes différentes. Avec
`CssBaseline`, H9 est ISO d'emblée et il ne reste que le vrai écart de N8.

C'est la leçon OpenAEV #34 sous une autre forme : **un banc qui ne charge pas
tout ce que l'hôte charge mesure autre chose que l'application.** Corrigé dans
les deux entrées du banc.

---

## 12. Page de login et écrans publics — mesuré sur l'app tournante

> **Cette section corrige une conclusion antérieure de ma part.** En lecture de
> code seule, j'avais écrit que la page de login « n'a pas de `<Paper>` du tout »
> et que rien ne lisait le champ de palette fautif. La mesure au DOM dit
> autrement : le formulaire **est** une surface `MuiPaper`/`MuiCard`, et elle est
> peinte par `background.secondary` — **exactement le champ qui portait le défaut
> OpenAEV**. Mon grep cherchait `<Paper>` dans `public/` et le token
> `--bg-elevation-highlight` ; le formulaire passe par le wrapper `Card`, donc
> les deux l'ont manqué. La lecture de code ne remplace pas la mesure.

App servie sur `127.0.0.1:3011`, backend de **cette branche** sur `127.0.0.1:4011`,
préfixe d'index isolé (`papercti`) pour ne pas toucher aux données de dev
partagées. Pin re-prouvé par les octets servis par cette app : `transparency-15`
×29, `transparency-40` ×0, ancien nom de marque déclaré 0 fois, `p-8` présent.

Le backend de la branche compte : il sert `theme_primary: #42caff`, la valeur
introduite par sa propre migration. Un backend plus ancien aurait servi
`#0fbcff` et fait mesurer la mauvaise chose.

### Ce qui est mesuré

| surface | thème sombre | thème clair |
|---|---|---|
| carte du formulaire (`MuiCard`, padding 24) | `rgb(12,21,36)` = **`#0C1524`** — **hors échelle** | `rgb(255,255,255)` = **layer 1** ✅ |
| colonne de contenu | `rgb(7,13,24)` = **layer 0** ✅ | layer 0 ✅ |
| aside | dégradé en dur | dégradé en dur |

Les couches, relevées sur la page elle-même : layer 0 `#070d18`, layer 1
`#0d172b`, layer 2 `#13213e`, layer 3 `#1f3965`.

### D'où vient l'écart

`Card.tsx:68-71` :

```ts
const isCustomCardColor = hasCustomColor(theme, 'theme_paper');
const backgroundColor = isCustomCardColor
  ? theme.palette.background.paper       // thème client → couleur du client
  : theme.palette.background.secondary;  // thème par défaut → littéral en dur
```

et `ThemeDark.ts:96-98` :

```ts
secondary: paper === THEME_DARK_DEFAULT_PAPER ? '#0C1524' : (paper ?? '#0C1524'),
```

`#0C1524` n'est **aucun** des quatre pas. Distance RGB aux couches : layer 1 → **7**,
layer 0 → 15, layer 2 → 29, layer 3 → 77. Il vise layer 1 et le rate de peu.

En clair, `ThemeLight.ts:98-100` pose `#FFFFFF`, qui **est** exactement layer 1 :
**l'écart est propre au thème sombre**.

### Ce n'est pas le même défaut qu'OpenAEV, mais c'est le même champ

| | OpenAEV | OpenCTI |
|---|---|---|
| champ | `background.secondary` | `background.secondary` |
| mécanisme | résolvait sur `--bg-elevation-highlight-layer-0`, dont la valeur **est** celle de layer 2 | **littéral en dur** `#0C1524`, sur aucune couche |
| symptôme | panneau 2 crans trop haut | carte à 7 unités RGB de layer 1, sombre seulement |
| ampleur | 1 surface | **toutes les cartes du thème par défaut** |

### Pourquoi je ne corrige pas

`background.secondary` a **9 consommateurs directs**, et `Card.tsx` en est un —
c'est-à-dire **les 219 sites de Card** (décompte mesuré ; le brief annonçait 164), explicitement hors périmètre de cette
vague. Passer `#0C1524` au token layer 1 est une seule ligne, mais elle repeint
toutes les cartes du produit en thème sombre par défaut. Ce n'est pas une
correction de vague pilote, c'est une décision à part entière.

**Mesuré, chiffré, remonté — pas corrigé.** À toi.

### Aucun champ de palette rendu orphelin par cette vague

`tsc --noEmit` passe sans erreur après régénération du pont : aucune clé lue par
`ThemeDark`/`ThemeLight` n'a disparu. Relevé au passage, **antérieur à cette
vague** : `designSystem.background.bg2` et `bg3` sont déclarés et lus zéro fois.
Signalé, pas touché.

---

## 13. Checkpoint navbar — application réelle, cinq états, deux niveaux, trois thèmes

App servie sur `127.0.0.1:3011`, backend de la branche sur `127.0.0.1:4011`,
préfixe d'index isolé. Authentification par **jeton Bearer** — aucun mot de
passe saisi dans un champ. Thème client réel créé en base (`PaperClient`,
`theme_paper #3b2450`, `theme_primary #ff8a3d`), pas simulé.

### Les cinq états, mesurés (thème sombre)

| état | fond | barre gauche | bordure interne | outline |
|---|---|---|---|---|
| repos | `rgba(0,0,0,0)` | `2px` transparente | transparente | `3px none` |
| **survol** | **`rgb(19,33,62)`** | **transparente** | transparente | `3px none` |
| **focus** (Tab réel) | inchangé | `2px rgb(66,202,255)` | **`2px solid rgb(66,202,255)`** | `0px none` |
| **sélection niveau 1** | **`srgb(0.259,0.792,1)/0.1`** = marque à 10 % | `2px rgb(66,202,255)` | — | — |
| **sélection niveau 2** | `rgba(0,0,0,0)` — **sans fond** | transparente au repos | `2px` à la couleur de marque au focus | — |

Conforme à la Figma sur les trois points annoncés :

- **survol = fond seul, sans barre à gauche** ✅ — la barre gauche reste
  `rgba(0,0,0,0)` pendant que le fond passe à `rgb(19,33,62)`. C'est le
  correctif #124.
- **focus = bordure interne** ✅ — `2px solid` à la couleur de marque.
- **sélection niveau 1 avec fond, niveau 2 sans fond** ✅.

### Deux pièges de mesure, corrigés plutôt que publiés

1. **Le survol ne se déclenchait pas.** `hover({ force: true })` laissait le
   fond à `rgba(0,0,0,0)` et donnait « aucun changement au survol ». Il faut un
   **vrai déplacement de souris** (`mouse.move` sur le centre de la rangée).
2. **Le focus paraissait absent au niveau 1.** `locator.focus()` ne met pas
   `:focus-visible`, donc la bordure interne ne s'appliquait pas et la mesure
   ressemblait à un défaut WCAG 2.4.7. Avec une **vraie tabulation**,
   `:focus-visible` est vrai et la bordure est bien là. Vérifié avant d'écrire
   quoi que ce soit : **il n'y a pas de défaut d'accessibilité ici.**

Une troisième erreur avait faussé la première passe : le rail se replie par
**son** bouton `Expand` ; prendre « le dernier élément cliquable du nav »
attrapait une rangée et **naviguait ailleurs**, ce qui faisait mesurer un autre
écran.

### Ce que le focus confirme au passage

`outline` passe de `3px none` à `0px none` sous focus : la règle
`:focus { outline: 0 }` du produit (`static/css/index.css:26`) s'applique bien.
**L'indicateur survit quand même**, parce que #123 en a fait une bordure et pas
un anneau. C'est exactement l'argument de LIBRARY-FEEDBACK #35 — vérifié ici sur
l'application réelle, pas déduit.

### Thème client — la teinte de marque suit

| | sélection niveau 1 | focus niveau 2 |
|---|---|---|
| sombre | `srgb(0.259,0.792,1)/0.1`, barre `#42caff` | bordure `#42caff` |
| clair | `srgb(0,0.082,0.659)/0.1`, barre `#0015a8` | bordure `#0015a8` |
| **client** | **`srgb(1,0.541,0.239)/0.1`**, barre **`#ff8a3d`** | bordure **`#ff8a3d`** |

C'est la preuve de bout en bout du correctif de `NavBar.tsx:101` (§0.4) : avant
le renommage, cette colonne aurait affiché le bleu Filigran.

---

## 14. Arbitrages Sandy — troisième tour, et ce qu'ils ont produit

| # | décision | état |
|---|---|---|
| fusion `master` → `design-system/current` | go, **règle d'or** : master d'abord, puis ré-application des sessions d'implémentation par-dessus | **poussée** (`5722cda3f6`) |
| login | correctif **au site**, pas sur le champ de palette | **fait**, mesuré avant/après |
| thème client | base par couche, surface **et** bordure ; bordure = couleur des cartes du client en thème personnalisé | **câblé**, arête absente montrée |
| `title` / `action` | props adoptées à terme, **pas dans cette vague** — inventaire d'abord | **inventaire ci-dessous** |
| dégradé `ExperienceCard` | **hors périmètre**, comme les semi-transparents | listé, non converti |
| T1 / T2 / N7 | non convertis tant que (b) n'est pas tranché | non convertis |

---

## 15. Login — correctif au site, mesuré avant/après

Le correctif est **au site d'appel**, pas sur `background.secondary` : `LoginPage.tsx`
pose `backgroundColor: 'background.paper'` sur ses deux `Card`. Le champ de
palette reste **intact** pour ses 9 consommateurs et les 219 autres cartes.

`background.paper` résout sur `--bg-elevation-default-layer-1` et **continue de
suivre le `theme_paper` d'un client** — c'est déjà ce que `Card` fait sur sa
branche « thème personnalisé ». Aucune perte.

Mesuré sur l'app tournante, correctif mis de côté puis rétabli pour obtenir un
vrai avant :

| thème | avant | après |
|---|---|---|
| **sombre** | `rgb(12,21,36)` = `#0C1524`, **hors échelle** | **`rgb(13,23,43)` = LAYER 1** ✅ |
| clair | `rgb(255,255,255)` = LAYER 1 | `rgb(255,255,255)` — **inchangé** ✅ |

Conforme à la prévision : **seul le sombre bouge**. Les deux surfaces de la page
sont traitées (la carte du formulaire et la carte « aucun fournisseur
d'authentification »), pas seulement celle qui se voit par défaut.

---

## 16. Thème client — contrat câblé, arête absente assumée

Câblé dans `useFdsThemeScope`, le **seul écrivain** des propriétés que la lib lit
sur la racine. Quand la couleur de panneau s'écarte du défaut du mode, l'hôte
redéclare **la base par couche, surface ET bordure** :

```
--bg-elevation-default-layer-1        : <theme_paper du client>
--border-elevation-subtle-soft-layer-1: <theme_paper du client>
```

Couche 1 seulement : c'est l'élévation par défaut du Paper, et le client fournit
exactement une couleur. Retour à un thème intégré → les deux propriétés sont
**retirées**, pas laissées en surcharge morte.

Mesuré sur l'app, Paper de la lib monté dans la cascade réelle :

| thème | surface | bordure composite | ratio bordure/surface |
|---|---|---|---|
| sombre | `rgb(13,23,43)` | `rgb(17,31,58)` | **1,091** |
| clair | `rgb(255,255,255)` | `rgb(239,239,240)` | **1,149** |
| **client** (`#3b2450`) | **`rgb(59,36,80)`** | **`rgb(59,36,80)`** | **1,000** |

**L'arête disparaît en thème client** — 15 % de la couleur du client sur cette
même couleur recompose exactement la couleur. C'est la conséquence assumée de
l'arbitrage : **montrée, pas corrigée**.

---

## 17. `title` / `action` — inventaire avant adoption

Adoption décidée, **hors de cette vague**. Voici ce qu'il faut savoir avant.

### Population

| motif | nombre |
|---|---|
| `Typography variant="h4"` dans le produit | **37** |
| `Typography variant="h3"` | **84** |
| dont un `h4` immédiatement suivi d'un `<Paper>` ou `<Card>` | **4** |
| parmi les 28 Paper du périmètre : titre **hors** surface | **2** (N4, N7) |
| parmi les 28 : bandeau de titre **dans** la surface | **8** (H1-H8) |
| parmi les 28 : titre dans la surface, sans bandeau | **1** (H9) |

### Typographie actuelle vs celle de la lib — MESURÉE, et je corrige une erreur

> **Correction.** J'ai d'abord écrit, en lisant `ThemeDark.ts`, que le produit
> force `lowercase` sur `h3` et `h4` et que l'adoption **changerait le texte
> affiché**. Sandy a repris ce point. **C'est faux.** La déclaration existe bien
> dans `typography.h3`/`h4` (lignes 305 et 317), mais elle est **neutralisée** par
> `MuiTypography.styleOverrides.root { textTransform: 'none' }`
> (`ThemeDark.ts:673-680`), qui gagne sur les styles de variante. Mesuré sur le
> DOM : la classe emotion émise contient `text-transform: none`, pas `lowercase`.
> Le `::first-letter: uppercase` survit, mais il n'a plus rien à recapitaliser.
>
> **Conséquence : le texte affiché NE CHANGE PAS.** L'adoption est un changement
> de style seul. Le `lowercase` du thème est du code mort.
>
> Troisième fois dans cette vague que lire le thème donne une réponse que la
> mesure contredit — après le `<Paper>` de la page de login et le focus de la
> navbar.

Mesuré sur les trois cas représentatifs, thème sombre :

| | N4 / N7 (`h4`) | H9 (`h3`) | lib (rangée `title`) |
|---|---|---|---|
| casse rendue | **`none`** | **`none`** | **`none`** — identique |
| texte rendu | inchangé | inchangé | **inchangé** |
| taille | 12px | 13px | 12px |
| graisse | **500** | 400 | **400** |
| famille | IBM Plex Sans | **Geologica** | IBM Plex Sans |
| couleur | primaire `rgb(242,242,243)` | primaire | **secondaire `rgb(175,176,182)`** |
| hauteur | **15px** | **15px** | **24px** |

Ce qui bouge réellement : **+9px de hauteur** par en-tête, la graisse de `h4`
(500 → 400), la famille de `h3` (Geologica → IBM Plex Sans) et la couleur
(primaire → secondaire) sur les trois. Planches : `titles-dark.png`,
`titles-light.png`.

### Le piège structurel — mesuré, pas repris de confiance

Dès qu'une des deux props est posée, le Paper rend :

```
<div class="flex flex-col gap-2">     ← ENVELOPPE, ne reçoit RIEN du consommateur
  <div class="flex h-6 …">Titre</div>
  <div class="… layer-1 p-6 {className}">…</div>   ← la SURFACE porte le className
</div>
```

`className` et `style` restent sur la **surface**. Un consommateur qui passe
`flex-1` ou `height: 100%` les applique donc à l'intérieur, pendant que
l'enveloppe garde sa taille naturelle. Reproduit à l'identique dans un parent
`display:flex; flex-direction:column; height:300px` :

| | hauteur rendue |
|---|---|
| sans `title` — `flex-1` sur la racine | **188px** |
| avec `title` — enveloppe non stylée | **104px** |
| （dont la surface interne） | 72px |

**Le panneau perd 84px.** C'est l'effondrement observé côté OpenAEV, réglé
là-bas en passant le conteneur produit en **grille**.

**Sites d'OpenCTI concernés** : `StreamConsumersDrawer` (N8, `height: 100%`),
`ImportFilesFormSelector` (N11, parent `height:100% flex column`) et
`ExperienceCard` (G1, `height:100%` + `flex:1`). Les trois devront passer leur
conteneur en grille **avant** que `title`/`action` y soient adoptés.

---

## 18. `ExperienceCard` — hors périmètre, listé

`private/components/settings/experience/ExperienceCard.tsx:57` peint
`linear-gradient(135deg, alpha(accent,.08), transparent 60%)` et le shorthand
`background` **annule le fond du Paper** (mesuré `rgba(0,0,0,0)` dans les trois
thèmes). Le Paper de la lib peint un fond opaque et n'expose ni dégradé ni
transparence.

**Hors périmètre, au même titre que les conteneurs semi-transparents.** Non
converti, listé ici pour que la prochaine vague ne le reprenne pas par
inadvertance — même statut que `DetailHero` côté OpenAEV.


---

## 19. Padding asymétrique — tranché : uniforme 16px, option (b) abandonnée

**Décision de Sandy, prise SUR PIÈCE après lecture des planches** (`asym-dark.png`,
`asym-light.png`, cellules à largeur fixe et contenu identique) : les trois sites
passent à **`padding={16}` uniforme**.

**N7 va à 16 et non à 24**, alors que la règle du plus proche désignait 24 : c'est
volontaire, Sandy préfère l'homogénéité des trois sites à l'application stricte
de la règle. Noté ici pour que personne ne « corrige » ce 16 en 24 plus tard en
croyant à un oubli.

**L'option (b) — padding par côté côté lib — est fermée.** Aucune prop à porter,
aucune session lib à lancer. Ce n'est **pas un renoncement technique** : la
faisabilité était chiffrée (échelle inchangée, ajout additif et non cassant, 20
classes à safelister dont 12 manquantes), et la mesure montrait bien que (b)
était exactement ISO là où (a) coûte de +8 à +28px. C'est un arbitrage produit
sur pièce : l'écart visible ne justifie pas l'ajout d'API.

### Ce qui a été converti, et ce qui ne l'a pas été

| site | décision | état |
|---|---|---|
| **N7** `StixDomainObjectAuthorKnowledge.jsx:273` | `padding={16}` | **converti** |
| **T1** `HistoryLineContent.tsx:107` | `padding={16}` | **NON converti — arrêt** |
| **T2** `UserHistoryLine.tsx:339` | `padding={16}` | **NON converti — arrêt** |

**Pourquoi T1 et T2 sont en arrêt.** Les deux portent `background: 0`, qui annule
le fond du Paper : ce sont les **conteneurs semi-transparents**, mis **hors
périmètre dès le brief initial** (« HORS PÉRIMÈTRE, déjà tranché : les conteneurs
semi-transparents »). Mesuré : fond rendu `rgba(0, 0, 0, 0)` dans les trois
thèmes, la page se voit au travers.

Les convertir ajouterait un fond **opaque** — une perte de fonctionnalité
visuelle que le Paper de la lib ne sait pas éviter, et qui n'a **pas** été
tranchée. La décision sur la bordure et l'ombre (D5) les couvre bien, elle ; la
transparence, non. Conformément à la règle « une perte assumée n'existe que si
Sandy l'a explicitement tranchée », les deux sites restent sur MUI en attendant
un arbitrage explicite.

---

## 20. Feuille de décision — les 14 surfaces restantes, par classe

Servie en local : **http://127.0.0.1:5311/decision.html** (`?mode=light` pour le
thème clair). Captures : `feuille-decision-dark.png`, `feuille-decision-light.png`.
**Rien n'est converti par cette page** — c'est un banc, et l'attente est
explicite : ne rien convertir avant que Sandy rende la feuille annotée.

**La condition posée est vérifiée** : les 14 surfaces restantes sont bien des
`<Paper>` **directs**, sauf la classe 7 qui n'en est pas une (voir plus bas).
État mesuré : **14 balises converties, 14 restantes** sur les 28 de départ.

| # | classe | population restante | écart qui commande la décision |
|---|---|---|---|
| 1 | **swap mécanique** | **0** | — |
| 2 | **ombre perdue** | **2** (+3 flottantes hors périmètre) | pas de bordure + ombre d'élévation MUI ; la lib fait l'inverse, non désactivable |
| 3 | **fond propre** | **3** | fond annulé (T1, T2) ou dégradé d'accent (G1) ; la lib peint opaque |
| 4 | **padding hors échelle** | **6** | 15px ×4, 20px ×2 ; hors échelle → 0px en silence |
| 5 | **surface hébergeant une structure** | **3** (déjà comptés ailleurs) | grille interne + `.paper-for-grid` non-layerée qui gagne (#16) |
| 6 | **gouttières de liste** | **0** en périmètre | motif déjà validé et appliqué sur N11/N12/N13 |
| 7 | **motif carte** | **219 sites** | **pas des Paper directs** |

### Deux classes sont vides, et pas pour la même raison

- **Swap mécanique : vide par épuisement.** Les 14 sites sans écart ont déjà été
  convertis dans cette vague (8 en-têtes SSO, N8, N11, N12, N13, H9, N7). Aucun
  des 14 restants n'est sans écart — chacun porte au moins un des motifs 2 à 5.
- **Gouttières de liste : classe traitée.** Le motif est validé et appliqué ; ne
  restent que les trois surfaces flottantes, hors périmètre par arbitrage.

### Classe 7 — la réponse à la condition

`Card.tsx` rend `Card` de MUI, qui compose `Paper` **en interne**. Ce ne sont
donc **pas des `<Paper>` directs** : les convertir n'est pas un échange de
balise mais un remplacement de composant, et leur fond passe par
`background.secondary` — le champ que le login contourne désormais au site.

Décompte mesuré aujourd'hui : **219 sites `<Card>` dans 166 fichiers**, dont
**174 portent `title=`** (36 d'entre eux un nœud composé), **34 portent `action=`**
et **30 sont des cartes-liens** (`to` ou `onClick`). Le brief annonçait 164 ;
l'écart est signalé, pas absorbé. **219 est le chiffre qui dimensionne le chantier Card.**

> **Ne pas « recorriger » vers 222, 216 ou 123.** Trois chiffres faux ont circulé
> avant celui-ci ; voici d'où ils venaient, pour que personne ne les restaure.
> **222 / 167** comptait *toutes* les balises `<Card>` du front, en y mêlant les
> **3 sites, dans 1 fichier**, qui utilisent le `Card` de **MUI** et non le wrapper
> produit (`StixDomainObjectAuthorKnowledge.jsx`) — 219 + 3 = 222, 166 + 1 = 167.
> **216 / 163** venait d'un filtre d'import ne reconnaissant que les chemins
> longs, qui ratait les trois imports relatifs `'./Card'` (`CardAccordion.tsx`,
> `CardNumber.tsx`, `CardStatistic.tsx`). **123** venait d'un `grep` de ligne,
> aveugle aux balises ouvrantes multilignes : il en ratait 51.
> Le décompte de référence est l'analyseur à profondeur d'accolades — le même que
> celui de `scripts/check-fds-conformity.mjs` — qui distingue le wrapper produit
> du composant MUI par son import.

### Recouvrements assumés

Un site peut relever de deux classes ; il est rangé sous celle qui **commande**
sa décision, et son autre appartenance est nommée :

- N5, N6 — classe 4 (padding 20px) **et** classe 5 (grille interne)
- N9 — classe 2 (ombre) **et** classe 5 (cellule `.paper-for-grid`)
- F1, F2, F3 — classe 2 (ombre) **et** classe 6 (MenuList), **et** hors périmètre
  par l'arbitrage initial sur les surfaces flottantes

---

## 21. Classes 2, 4 et 5 converties — et trois trouvailles en cours de route

Validé par Sandy sur la feuille. **7 sites convertis.**

| classe | sites | avant → après, mesuré |
|---|---|---|
| 2 | N10 `ImageCarousel.tsx:143` | perd l'ombre MUI, gagne `1px` de bordure — **+2px** |
| 4 | N1, N2 `ConnectorWorksErrorLine.tsx:96,122` · N3 `DraftRoot.tsx:203` · N4 `ScaleConfiguration.tsx:209` | 15px → `padding={16}` — **+2px** |
| 4+5 | N5 `HeaderField.tsx:32` · N6 `QueryAttributeField.tsx:43` | 20px → `padding={24}` — **+8px** |

Sur N5/N6, `.paper-for-grid` ne combat **aucun** utilitaire de la lib : ces deux
sites ne posent pas de hauteur par classe, donc le contournement #16 n'est pas
nécessaire — contrairement à N8. Vérifié, pas supposé. Sur N10 le contournement
est repris par précaution et marqué sur place.

### 21.1 N9 était mal classé — erreur d'inventaire de ma part

Je l'avais mis en classe 2 (« ombre perdue »). La balise entière dit autre chose :
`EntitySettingCustomOverview.tsx:85` pose déjà **`boxShadow: 'none'`** *et* sa
propre bordure **`0.5px solid theme.palette.border.primary`**. Ma copie de banc
avait tronqué les deux propriétés, d'où une mesure fausse.

Conséquence : **la classe 2 ne contenait qu'un site en périmètre, N10.**

Et N9 **sort de la vague** : `border.primary` vaut `hexToRGB(theme_primary, 0.3)`,
c'est-à-dire **l'accent du client à 30 %**. Le convertir donne une bordure neutre
de 1px qui ne suit plus l'accent — une **perte d'information**, pas un changement
de style. Décision de Sandy : hors vague, avec T1, T2 et G1.

### 21.2 Définitivement hors vague Paper

| site | raison |
|---|---|
| T1 `HistoryLineContent.tsx:107` | `background: 0` — semi-transparent |
| T2 `UserHistoryLine.tsx:339` | `background: 0` — semi-transparent |
| G1 `ExperienceCard.tsx:57` | dégradé d'accent + fond annulé |
| **N9** `EntitySettingCustomOverview.tsx:85` | bordure `0.5px` à **l'accent du client à 30 %** |

Plus les trois surfaces flottantes F1, F2, F3, qui appartiennent à Dialog/Menu.

### 21.3 L'inventaire était incomplet : 7 surfaces Paper de plus

Elles sont **injectées par prop** — `<TableContainer component={Paper}>` — donc
un grep sur `<Paper` ne les voit pas. Le périmètre réel est **28 balises + 7
injectées = 35 surfaces Paper**.

| fichier | nb |
|---|---|
| `components/common/table/ChangesTable.tsx:38` | 1 |
| `private/components/data/connectors/ConnectorWorkLine.tsx:190` | 1 |
| `private/components/data/tasks/TasksList.jsx:485,519` | 2 |
| `private/components/observations/indicators/DecayDialogContent.tsx:152` | 1 |
| `private/components/profile/api_tokens/TokenList.tsx:125` | 1 |
| `private/components/settings/users/UserTokenList.tsx:117` | 1 |

### 21.4 Un défaut que j'avais livré, et qui est corrigé

En convertissant `TokenList` et `UserTokenList` au lot pilote, j'ai remplacé leur
import MUI par celui de la lib — ce qui a **silencieusement repointé leur
`component={Paper}`** sur le Paper de la lib. Non mesuré, non voulu, parti dans
`fd4f990567` avec une CI verte.

Corrigé : MUI est rendu à `component=` sous l'alias `MuiPaper`, la balise
`<Paper>` reste celle de la lib, et les deux fichiers sont déclarés **MIXTES**
dans `migration-state.json` — exactement le cas pour lequel
`mixed.allowMuiPaperFor` existait. La garde d'import y est désarmée avec sa
raison, `no-hardcoded-padding` reste armée.

**Pourquoi MUI doit rester là** : un composant passé à MUI via `component=`
reçoit des props MUI (`variant`, `sx`) que le Paper de la lib n'accepte pas.

---

## 22. AUDIT COULEURS — les 35 surfaces, mesuré au DOM

Planche : `audit-dark.png`, `audit-light.png` — servie sur
**http://127.0.0.1:5311/audit.html**.

### La mesure décisive

`MuiPaper` peint `palette.background.paper`, que le pont câble sur
`--bg-elevation-default-layer-1`. Mesuré au DOM, dans le vrai thème, sur un
`MuiPaper` **sans surcharge** face au `Paper` de la lib :

| thème | MuiPaper nu | Paper lib couche 1 | verdict |
|---|---|---|---|
| sombre | `rgb(13,23,43)` | `rgb(13,23,43)` | **même pixel** |
| clair | `rgb(255,255,255)` | `rgb(255,255,255)` | **même pixel** |
| client `#3b2450` | `rgb(59,36,80)` | `rgb(59,36,80)` | **même pixel** |

**Donc oui : ton attente est juste, et toute surface qui ne surcharge pas son
fond peint déjà exactement le token de la lib.** C'est prouvé, pas affirmé.

### Fond — 32 coïncident, 3 divergent

| surfaces | verdict |
|---|---|
| **32 / 35** | aucune surcharge → **coïncident au pixel** |
| T1 `HistoryLineContent.tsx:107` | `background: 0` → `rgba(0,0,0,0)`, la page se voit au travers |
| T2 `UserHistoryLine.tsx:339` | `background: 0` via `classes.paper` — **la surcharge est dans le makeStyles, pas sur la balise** |
| G1 `ExperienceCard.tsx:57` | dégradé d'accent, fond annulé |

Les trois sont déjà hors vague. **Aucune surface Paper du périmètre ne peint un
littéral en dur.**

### Le vrai littéral en dur est AILLEURS : le motif carte

C'est la ligne que tu cherchais, et elle n'est pas dans les 35.

| | sombre | clair |
|---|---|---|
| `Card` (219 sites) peint `background.secondary` | **`rgb(12,21,36)` = `#0C1524`** | `rgb(255,255,255)` |
| couche 1 de la lib | `rgb(13,23,43)` | `rgb(255,255,255)` |
| verdict | **DIVERGE — littéral hors pont** | coïncide |

`#0C1524` n'est **aucun** pas de l'échelle. En clair le littéral vaut `#FFFFFF`,
qui **est** layer-1 : l'écart est **propre au thème sombre**, sur **219 sites**.
C'est le même défaut que la carte du login, dont la correction au site n'a traité
qu'un cas sur 223.

### Bordure — aujourd'hui ce n'est PAS un token

| surfaces | ce qui est peint aujourd'hui | origine |
|---|---|---|
| 21 « outlined » | `rgba(255,255,255,0.12)` sombre · `rgba(0,0,0,0.12)` clair | **défaut interne de MUI** — le produit ne déclare **jamais** `palette.divider` |
| 7 sans bordure | rien, + une ombre d'élévation MUI | — |
| **N9** | `0.5px rgba(66,202,255,0.3)` sombre · `rgba(0,21,168,0.3)` clair | **`border.primary` = l'accent du CLIENT à 30 %** |
| après conversion | `1px` du token `--border-elevation-subtle-soft` à 15 % | pont de tokens |

**Aucune bordure du périmètre ne vient d'un token Filigran aujourd'hui.** La
conversion est la première fois qu'elle en vient une. Et N9 est la seule qui
suive le client — d'où sa sortie de vague.

### Titres et actions — la couleur suit le client, celle de la lib non

| | `h4` (N4, N7) | `h3` (H9) | rangée `title` de la lib |
|---|---|---|---|
| taille / graisse | 12px / **500** | 13px / 400 | 12px / 400 |
| famille | IBM Plex Sans | **Geologica** | IBM Plex Sans |
| couleur | **`text_color`** = `theme_text_color` du client | idem | **`--text-default-secondary`**, token fixe |
| casse rendue | `none` | `none` | `none` — identique |
| hauteur | 15px | 15px | **24px** |

La divergence qui compte n'est pas la typographie, c'est la **couleur** : le titre
produit suit le `theme_text_color` du client, celui de la lib est un token fixe.
**Adopter `title`/`action` fait perdre au titre le suivi de la couleur de texte du
client.** À peser dans ta décision.

---

## 23. Suivi séparé — les quatre barres qui peignent sur toute la largeur

**Décidé par Sandy : pas maintenant.** Consigné ici pour ne pas le perdre, avec le
chiffrage et le fichier qui montre déjà la bonne forme.

### Le motif

Quatre barres flottantes peignent leur fond sur **toute la largeur de la fenêtre**
et ne décalent que leur **contenu**, par `padding-left` :

| fichier | ligne du décalage | empilement déclaré |
|---|---|---|
| `components/graph/GraphToolbar.tsx` | `paddingLeft: navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH` (58) | `zIndex: 1` (57) |
| `private/components/common/containers/ContainertKnowledgeTimeLineBar.tsx` | idem (91) | `zIndex: 1` (23) |
| `private/components/common/files/workbench/WorkbenchFileToolbar.jsx` | idem (176) | `zIndex: 1` (31) |
| `private/components/settings/sub_types/ToolBar.tsx` | idem (176) | `zIndex: 1` (31) |

Mesuré au DOM sur le graphe de connaissance et la chronologie, fenêtre 1440,
rail ouvert : la barre fait **1440 px de large**, commence à **x = 0**, et son
fond recouvre donc les **180 px** du rail. Le décalage du contenu est correct
(180 px = `OPEN_BAR_WIDTH`, 48 px replié) : ce n'est pas un problème de valeur,
c'est un problème de **surface peinte**.

### Pourquoi c'est fragile

Ces quatre barres ne sont correctes que **parce qu'une autre surface les masque**.
Elles dépendent du rail pour ne pas se voir, au lieu de ne pas se peindre là.
C'est exactement ce qui a transformé une propriété manquante sur le rail
(`z-index`) en régression visible sur quatre écrans — voir `LIBRARY-FEEDBACK.md`
n° 38. Le correctif appliqué (`.app-navbar { z-index: 1200 }`) rétablit le rendu
mais **ne retire pas la dépendance** : il remet le couvercle.

### La forme correcte existe déjà dans le produit

`private/components/data/ToolBar.jsx:97` fait la même chose avec la bonne
propriété :

```js
marginLeft: navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH,
```

Avec `marginLeft`, la barre **ne commence pas** avant la fin du rail : elle ne
peint rien sous lui, et son rendu ne dépend plus d'un empilement. Mesuré sur la
liste des rapports avec 21 lignes sélectionnées : la barre reste dans la zone de
contenu, aucun recouvrement du rail.

### Proposition, quand ce sera repris

Passer les quatre `paddingLeft` en `marginLeft` — 4 fichiers, 4 lignes — puis
retirer le `z-index: 1200` du rail et vérifier que le test de retrait de
l'entrée 38 passe toujours. Le gain n'est pas visuel : c'est que la coque cesse
d'être responsable de masquer le contenu des écrans.

**Réserve à lever avant de le faire** : `marginLeft` réduit la largeur utile de la
barre de 48 ou 180 px selon l'état du rail. Il faut vérifier au DOM que les
contrôles de chacune des quatre barres tiennent dans la largeur restante à
1024 px, sinon le remède déplace le défaut.
