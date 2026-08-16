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
c'est-à-dire **les 164 sites de Card**, explicitement hors périmètre de cette
vague. Passer `#0C1524` au token layer 1 est une seule ligne, mais elle repeint
toutes les cartes du produit en thème sombre par défaut. Ce n'est pas une
correction de vague pilote, c'est une décision à part entière.

**Mesuré, chiffré, remonté — pas corrigé.** À toi.

### Aucun champ de palette rendu orphelin par cette vague

`tsc --noEmit` passe sans erreur après régénération du pont : aucune clé lue par
`ThemeDark`/`ThemeLight` n'a disparu. Relevé au passage, **antérieur à cette
vague** : `designSystem.background.bg2` et `bg3` sont déclarés et lus zéro fois.
Signalé, pas touché.
