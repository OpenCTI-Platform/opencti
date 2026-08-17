# Paper wave — measured reference

What a later reader needs from this wave: the reference measurements, the
decisions with their reason, what was deliberately NOT converted, and the traps
that cost time. Organised by purpose, not by the order the work happened.

Companion documents:
- `LIBRARY-FEEDBACK.md` — every library-imposed gap, numbered, each with a
  removal test. Entries 30-39 come from this wave.
- `migration-state.json` — the machine-readable contract the conformity gate
  reads (`paperPattern`, `forbiddenPatterns`, `wiredFiles`).

---

## 1. Pin and gate

Wave opened at pin `a22b188b`, closed at `f86e76e`. Every gate below was run on
the INSTALLED build and proved by the SERVED BYTES, never by the lockfile.

**Why served bytes.** The lockfile records what resolution was requested; only
the bytes say what the browser will execute. Reading the changelog or the types
instead has cost this pilot real time twice.

Gate points, all four verified at `a22b188b`:

| gate point | result |
|---|---|
| `padding` prop on the 0/8/16/24/32 scale | five classes `p-0 p-2 p-4 p-6 p-8` present in the shipped CSS |
| `title` / `action` as real props | present |
| host-theme contract, BOTH directions | per-layer base repaints surface and border; overriding the semantic alias does nothing |
| border on `--border-elevation-subtle-soft` | present, at 15 % dilution |

**Bridge freshness is verified by hashing, never by trusting a sibling
checkout.** `theme.css` sha256 at both pins: `87f2d00abcbf4b6a` — unchanged, so
the token bridge was not regenerated for the closing bump.

**Bump procedure, learned the hard way.** Stop the servers BEFORE purging; purge
`node_modules/.vite` AND the package directory; reinstall; restart; then force
discovery of the dynamic-import routes from a browser before concluding
anything. A 3-second install is not evidence — the chunk filename changing is
(`chunk-CBU64Y6F` → `chunk-WX3UX5G2` at the closing bump).

### Dead references after a token rename — three found, all three silent

The `-transparency` → `-transparency-10` rename killed three product references.
Neither `tsc`, nor eslint, nor the build complained about any of them.

| reference | site | why silent |
|---|---|---|
| `var(--color-filigran-brand-primary-transparency)` READ | `TopBarIconLink.tsx:8` | a dangling `var()` inside a string |
| the same token DECLARED | `NavBar.tsx:101` | the rail declared the old name while the library read the new one, so a selected row painted Filigran blue instead of the customer accent |
| the dead literal ASSERTED | `TopBarIconLink.test.tsx:29` | the test asserted the dead string and stayed green |

**Rule this leaves.** After any token rename, search the product for BOTH shapes
— the utility class as a bare literal, and `var(--token)` inside a string — and
cross-check against the installed `dist/index.css`. Regenerating the bridge does
not surface them. `-transparency-50` was NOT renamed and was left untouched.

### Expected, not a regression

The warning colour darkens in LIGHT mode only: `--color-feedback-warning-primary`
`#e6700f` → `#b8550a`, tertiary `#884106` → `#572a05`; dark unchanged. Read at
`ThemeLight.ts:50,130,202`. Shown, not fixed.

---

## 2. Perimeter — 21 of 35 surfaces converted

The real perimeter was **35**, not the 28 announced: a `<Paper` grep never sees
the seven surfaces injected as `<TableContainer component={Paper}>`.

### Converted (21)

| group | sites |
|---|---|
| SSO headers | `AuthProviderGroupsFields` ×3, `AuthProviderOrganizationsFields` ×3, `AuthProviderUserInfoFields`, `HeaderStrategyForm` |
| pilot lot | `StreamConsumersDrawer`, `ImportFilesFormSelector`, `TokenList`, `UserTokenList`, `RequestAccessSettings` |
| padding on the scale | `ConnectorWorksErrorLine` ×2, `DraftRoot`, `ScaleConfiguration` (15→16), `HeaderField`, `QueryAttributeField` (20→24), `StixDomainObjectAuthorKnowledge` (asymmetric→16) |
| injected, form B | `DecayDialogContent`, `ConnectorWorkLine`, `TasksList` ×2 |
| lost shadow | `ImageCarousel` |

### Not converted (14), with the measured reason

| site(s) | reason |
|---|---|
| T1, T2 | semi-transparent containers — the library Paper has no translucent surface |
| G1 | gradient background — not expressible |
| N9 | border is `hexToRGB(theme_primary, 0.3)`, the customer's accent, not a token |
| F1-F3 | floating surfaces belonging to Dialog / Menu |
| injected form A ×3 | explicitly border-less; the library Paper always draws its edge |
| the dashboard tile | arbitrated out: 126 tiles, own luster gradient |
| `Card` wrapper + its sites | its own wave, sized in §7 |
| `ExperienceCard` | OpenAEV surface, out of this product's perimeter |

**Rule.** If the library component cannot reproduce something the product does
today, the site is NOT converted: it is listed with its reason and its
measurement. An assumed loss exists only where it was explicitly arbitrated.

---

## 3. Arbitrated rules

These are the durable decisions. Each is stated with the reason, because the
reason is what lets a later reader apply it to a site this wave never saw.

1. **Padding takes the nearest value on the scale.** 15px → 16, 20px → 24.
   A density that is already wrong is reproduced as-is rather than silently
   improved.
2. **Asymmetric paddings become a uniform 16px.** Three sites were concerned.
   Option (b) — teaching the library to express asymmetric padding — was priced
   (20 static safelisted classes, an out-of-scale development warning, emission
   tests) and abandoned as disproportionate for three sites.
3. **When the Paper carries the padding, the child's padding is REMOVED** —
   except where that padding carries meaning, in which case it stays and the
   reason is written at the site.
4. **Bare panel = Paper with an EXPLICIT padding equal to the site's current
   padding.** Never a default.
5. **Border: exactly what the library does.** The product never declared
   `palette.divider`, so no border in this perimeter came from a Filigran token;
   adopting the library edge is a gain, not a drift.
6. **Title outside the surface = Paper**, but `title`/`action` are adopted only
   if rendering stays ISO. They are NOT adopted in this product — see
   `LIBRARY-FEEDBACK.md` #37.

---

## 4. Product-side corrections made in this wave

Four fixes that were not tag swaps. Each is at the SITE that paints, never on a
shared field, so that consumers outside the question are untouched.

### The `#0C1524` literal — 219 cards

`Card.tsx` painted `palette.background.secondary`, a hardcoded literal that is
**no step of the elevation scale** (`#0C1524` against layer-1 `#0d172b`). In
light the same field is `#FFFFFF`, which IS layer-1, so the drift was dark-only
— and invisible to anyone reading the theme rather than the rendered pixel.

Collapsed to `background.paper`, which resolves to
`--bg-elevation-default-layer-1` through the bridge and already follows a
customer's `theme_paper`. A customised install renders exactly as before.

Fixed in the wrapper, deliberately not in the theme: repointing
`background.secondary` itself would have moved its seven other consumers — date
pickers, drawer header, saved-filters autocomplete, relationship header, chatbot
— which are inputs and chrome, not card surfaces. `CardAccordion` follows the
same correction, otherwise it would sit alone on the old value.

### The card border, in one line

`border: '1px solid var(--border-elevation-subtle-soft)'` in `Card.tsx`.

**Why not swap `CardMui` for the library Paper.** Surface colour and radius
already match (4px both sides), so the exchange would buy the border and nothing
else, while forcing 45 `sx` call sites onto `style`, giving 25
`variant="outlined"` sites a background they do not have, dropping the
asymmetric padding of 11 sites plus part of the dashboard tiles, and leaving a
hybrid the real Card wave would have to undo — the 45 `sx` sites paid twice.
Same rendering, none of the debt.

### Chart backgrounds — 8 factories

Fixing the card literal made a mismatch visible: charts painted
`background.secondary` inside a card that now painted layer-1. Eight factories
in `Charts.jsx` realigned onto the carrying surface. `radarChartOptions` has no
background line and stays transparent; `donutChartOptions` keeps its
`withBackground` branch.

**The distinction that decided the sweep.** A chart lives INSIDE the card and is
meant to be invisible against it. Inputs and bands live NEXT TO the card and are
meant to contrast: the three outlined-input consumers of `background.secondary`
paint `#0C1524`, which is the application's standard input colour, and
`DrawerHeader` sits on `background.nav` (`#070d18`), not on a card. Nothing else
was touched.

### Login page and the customer-theme contract

The login form is a `MuiCard` going through the `Card` wrapper, painted by
`background.secondary` — so it was corrected at the site, with
`backgroundColor: 'background.paper'` on both cards.

Customer theme: the host redeclares the **base per layer** for surface AND
border (`--bg-elevation-default-layer-1`,
`--border-elevation-subtle-soft-layer-1`) in `useFdsThemeScope`. Overriding the
semantic alias does nothing — substitution happens at computed-value time on the
declaring element. Assumed consequence, shown and not fixed: in a custom theme
the border takes the customer's card colour, so there is no visible edge.

---

## 5. A regression this wave shipped, and the fix

Found after the wave closed, on the running application. Kept here because the
mechanism generalises.

**Two defects, one missing contract.** The library `Navbar` declares neither an
anchoring inset nor a stacking level, so the host invents both — see
`LIBRARY-FEEDBACK.md` #38.

| | legacy MUI docked Drawer | this wave, before the fix | after |
|---|---|---|---|
| horizontal drift at a 1280px viewport | `fixed` paper — **0** | `sticky` + `top` only — **−120px** | **0** |
| stacking | paper at `z-index: 1200` | `auto`, so a `z-index: 1` bar won the pixel | **1200** |

Fixed in `design-system-host.css` with `left: 0` and `z-index: 1200` on
`.app-navbar`. `left: 0` gives sticky the horizontal inset it lacked and holds
for ANY overflow, because the inset resolves against the viewport rather than
the content width; the rail stays in flow, so its 48/180px column is still
reserved and the content does not shift.

**What this was NOT.** The horizontal scroll itself is not from this wave.
`private/Index.tsx` has carried `minWidth: 1400` on the shell since 2023-06-16
(`ad7f3340c8`), the threshold is identical on master and on this branch at four
viewport widths, and OpenAEV carries the same constraint. Raised as a separate
product issue, not touched here.

---

## 6. Gate and guards

The `paperPattern` motif in `check-fds-conformity.mjs`, driven entirely by
`migration-state.json`:

- `imported-from-library` — the file takes Paper from the library and no longer
  from MUI, including the deep default import `@mui/material/Paper`.
- `no-hardcoded-padding` — reddens if a padding reappears hardcoded on a library
  Paper, in `className`, `sx` or `style`.

Both guards were **seen red before being trusted green**: a `p-4` className, a
`style padding:15`, and a deep MUI import each reddened the gate on demand.

**MIXED files are declared, not dodged.** `TokenList` and `UserTokenList` keep
MUI's Paper for `TableContainer component=` — a component passed to MUI as a
prop receives MUI props the library Paper does not understand. Declared through
`mixed.allowMuiPaperFor` with the reason and the symbol allowed to remain.

The tag parser tracks brace depth rather than using a flat regex: an
`sx={{ … }}` contains `>` characters, and a regex stopping at the first one sees
a fragment of the tag.

---

## 7. Sizing for the next waves

Measured with the brace-depth parser that `check-fds-conformity.mjs` uses, split
by import so MUI's own `Card` is not counted as a wrapper call site:

| | count |
|---|---|
| `<Card>` sites, product wrapper | **219** in **166 files** |
| with `title=` | **174** (36 of them a composed node) |
| with `action=` | **34** |
| card-links (`to` / `onClick`) | **30** |
| `<Card>` sites using MUI's Card, out of scope | 3 in 1 file (`StixDomainObjectAuthorKnowledge.jsx`) |

> **Do not "re-correct" towards 222, 216 or 123.** Three wrong figures
> circulated; here is where each came from, so none is restored. **222 / 167**
> counted every `<Card>` tag in the front, mixing in the 3 MUI sites —
> 219 + 3 = 222, 166 + 1 = 167. **216 / 163** came from an import filter that
> only recognised long paths and missed three relative `'./Card'` imports
> (`CardAccordion.tsx`, `CardNumber.tsx`, `CardStatistic.tsx`). **123** came
> from a line grep blind to multi-line opening tags: it missed 51.

**`title`/`action` and the Card wave are one decision, not two.** 174 of the 219
sites pass `title=`, and the library title row cannot follow the host's text
colour (`LIBRARY-FEEDBACK.md` #37). The day that colour is reachable, 174 sites
become expressible in one move.

---

## 8. Follow-up: four bars that paint across the full width

Arbitrated as a separate follow-up, not part of this wave.

Four floating bars paint their background across the **whole viewport** and
offset only their CONTENT, with `padding-left`:

| file | offset line | declared stacking |
|---|---|---|
| `components/graph/GraphToolbar.tsx` | 58 | `zIndex: 1` (57) |
| `private/components/common/containers/ContainertKnowledgeTimeLineBar.tsx` | 91 | `zIndex: 1` (23) |
| `private/components/common/files/workbench/WorkbenchFileToolbar.jsx` | 176 | `zIndex: 1` (31) |
| `private/components/settings/sub_types/ToolBar.tsx` | 176 | `zIndex: 1` (31) |

Measured on the knowledge graph and the container timeline, 1440px viewport,
rail expanded: the bar is 1440px wide, starts at x=0, and its background covers
the rail's 180px. The content offset is correct (180px expanded, 48px collapsed)
— this is not a wrong value, it is a painted surface.

**Why it is fragile.** These bars are only correct BECAUSE another surface hides
them. They depend on the rail not to be seen, instead of not painting there. The
`z-index: 1200` fix restores the rendering but does not remove the dependency.

**The correct form already exists in this product.**
`private/components/data/ToolBar.jsx:97` uses `marginLeft` instead, so the bar
does not begin before the rail ends and its rendering depends on no stacking
order. Measured on the reports list with 21 rows selected: no overlap.

**Proposal, when this is picked up.** Move the four `paddingLeft` to
`marginLeft` — 4 files, 4 lines — then remove the rail's `z-index: 1200` and
check that entry #38's removal test still passes. **Reserve to lift first:**
`marginLeft` costs the bar 48 or 180px of usable width, so verify at the DOM
that each bar's controls still fit at a 1024px viewport, or the remedy just
moves the defect.

---

## 9. Measurement lessons

The traps that produced a wrong result, or nearly did. Each one is cheap to
avoid once named.

1. **A bench must load everything the real screen loads.** Measuring without
   `<CssBaseline />` — which `private/Index.tsx` renders — left MUI in
   content-box and the library in border-box, and produced two false heights.
   The bench loads all three stylesheets and `<CssBaseline />`.
2. **Unlayered host CSS beats the library's `@layer utilities`.** Measured:
   `h-full` lost to `.paper-for-grid`, 110px expected against 85px rendered.
3. **`hover({force})` does not fire hover, and `locator.focus()` does not set
   `:focus-visible`.** Both produced fake defects on the navbar; a real Tab
   shows the inset border.
4. **Verify the theme actually switched, not just that the request succeeded.**
   The user preference stores the theme's **id**; pushing the string `"light"`
   is compared against `'Light'`, resolves to nothing and falls back to dark
   silently. Four "light theme" runs were measured in dark before this was
   caught. Assert `document.documentElement.className` in every probe.
5. **Inspecting a component can report the host's value.** `Chip` sets its type
   class on the label only, so the chip ROOT inherits the surrounding font size:
   12px on the label, 14px on the root, both true. See
   `LIBRARY-FEEDBACK.md` #39.
6. **A reference build is not the same thing as the running application.** A
   conclusion measured on two self-built trees says nothing about what a user is
   looking at — window width and browser zoom decide what they see.
7. **Automated defect counters over-count.** A "clipped content" counter flagged
   chart tooltips, MUI switch thumbs and badges, all of which overflow by
   design. It was discarded rather than reported.
8. **Prove a guard red before trusting it green.**
