# Paper wave — measured reference

What a later reader needs from this wave: the reference measurements, the
decisions with their reason, what was deliberately NOT converted, and the traps
that cost time. Organised by purpose, not by the order the work happened.

**Which method is authoritative.** Every figure in this document, in the PR body
and in `LIBRARY-FEEDBACK.md` comes from `scripts/count-surfaces.mjs`, which
imports the same analyser the conformity gate uses
(`scripts/lib/jsx-opening-tags.mjs`: brace-depth tag parsing, import origin
resolved including relative paths). Re-run it rather than trusting a number in
prose:

```
node fds-migration/scripts/count-surfaces.mjs
```

No figure below comes from a grep. Where a grep-derived figure circulated
earlier, it is named and corrected in §6.

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

**Bridge freshness is verified by hashing, never by trusting a sibling
checkout.** `theme.css` sha256 at both pins: `87f2d00abcbf4b6a` — unchanged, so
the token bridge was not regenerated for the closing bump.

**Bump procedure, learned the hard way.** Stop the servers BEFORE purging; purge
`node_modules/.vite` AND the package directory; reinstall; restart; then force
discovery of the dynamic-import routes from a browser before concluding
anything. A 3-second install is not evidence — the chunk filename changing is
(`chunk-CBU64Y6F` → `chunk-WX3UX5G2` at the closing bump).

### Dead references after a token rename

A `-transparency` → `-transparency-10` rename killed three product references in
this wave, and **all three were silent**: neither `tsc`, nor eslint, nor the
build complained about any of them.

**Rule this leaves.** After any token rename, search the product for BOTH shapes
— the utility class as a bare literal, and `var(--token)` inside a string — and
cross-check against the installed `dist/index.css`. Regenerating the bridge does
not surface them. `-transparency-50` was NOT renamed and was left untouched.

---

## 2. Perimeter — 25 library-Paper call sites in 19 files

Counted by the analyser, not by hand:

| | count |
|---|---|
| `<Paper>` call sites importing from the library | **25** in **19 files** |
| files still importing MUI's `Paper` | **7** |

Two earlier figures were wrong for two different reasons, and both are worth
knowing. **21 "surfaces"** was hand-kept and folded a group of identical headers
into one; the analyser counts call sites, and a file may hold several (three in
each of two SSO field components, two in four others). **27** was the analyser's
own first answer, and it counted two `<Paper>` occurrences written inside a
COMMENT — the MIXED-file note at the top of `TokenList.tsx` and
`UserTokenList.tsx`. The analyser now blanks comments before matching, which also
stops a commented padding example from reddening the gate. The tree is the truth:
**25 sites, 19 files**.

The perimeter examined was wider than the sites converted: a `<Paper` grep never
sees the surfaces injected as `<TableContainer component={Paper}>`, which is how
seven more entered the inventory during the wave.

### Not converted (14), with the measured reason

| site(s) | reason |
|---|---|
| T1, T2 | semi-transparent containers — the library Paper has no translucent surface |
| G1 | gradient background — not expressible |
| N9 | border is `hexToRGB(theme_primary, 0.3)`, the customer's accent, not a token |
| F1-F3 | floating surfaces belonging to Dialog / Menu |
| injected form A ×3 | explicitly border-less; the library Paper always draws its edge |
| the dashboard tile | arbitrated out: 126 tiles, own luster gradient |
| `Card` wrapper + its sites | its own wave, sized in §6 |
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

## 4. Two rules the product-side corrections leave

Four surfaces were corrected in this wave rather than swapped: the `#0C1524`
literal on 219 cards, the card border, eight chart factories and the login page.
The diffs are in git and each site carries its reason in a comment. Two rules
transfer.

1. **Correct at the SITE that paints, never on the shared field.** Repointing
   `background.secondary` itself would have moved its seven other consumers —
   date pickers, drawer header, saved-filters autocomplete, relationship header,
   chatbot — which are inputs and chrome, not card surfaces, and were never part
   of the question.
2. **"Inside the surface" and "next to the surface" are not the same case.** A
   chart lives INSIDE the card and is meant to disappear against it, so it
   follows the card. Inputs and bands live NEXT TO it and are meant to contrast,
   so they keep their own colour. This distinction is what stopped the card fix
   from cascading into five unrelated surfaces.

## 5. Gate and guards

The `paperPattern` motif in `check-fds-conformity.mjs`, driven entirely by
`migration-state.json`:

- `imported-from-library` — the file takes Paper from the library and no longer
  from MUI, including the deep default import `@mui/material/Paper`.
- `no-hardcoded-padding` — reddens if a padding reappears hardcoded on a library
  Paper, in `className`, `sx` or `style`.

Both guards were **seen red before being trusted green**, on a real converted
file, for every shape they claim to catch:

| shape | verdict |
|---|---|
| `className="p-4"`, alone or first in the list | RED |
| `className="px-2"`, `pt-[15px]` in leading position | RED |
| `className="flex p-4 flex-col"` | RED |
| a padding AFTER a nested object: `style={{ nested: { a: 1 }, padding: 8 }}` | RED |
| a NAMED object: `style={paperStyle}` where `paperStyle` declares a padding | RED |
| a deep MUI import, `@mui/material/Paper` | RED |
| a commented example carrying a padding class | green, correctly |
| classes without padding | green |

The named-object shape is not hypothetical: `RequestAccessSettings.tsx` passes
`style={paperStyle}`, and `paperStyle` is precisely the object this wave emptied
of its padding — a regression there would have been invisible. The guard resolves
the identifier back to its `const` in the same file.

**Declared limits, not implied ones.** A padding assembled at runtime (clsx, a
variable, a template hole), an object imported from another module, or one spread
from a prop: no static reader follows those, and the guard says so in its
comment.

**MIXED files are declared, not dodged.** `TokenList` and `UserTokenList` keep
MUI's Paper for `TableContainer component=` — a component passed to MUI as a
prop receives MUI props the library Paper does not understand. Declared through
`mixed.allowMuiPaperFor` with the reason and the symbol allowed to remain.

The tag parser tracks brace depth rather than using a flat regex: an
`sx={{ … }}` contains `>` characters, and a regex stopping at the first one sees
a fragment of the tag.

---

## 6. Sizing for the next waves

Measured with the brace-depth parser that `check-fds-conformity.mjs` uses, split
by import so MUI's own `Card` is not counted as a wrapper call site:

| | count |
|---|---|
| `<Card>` sites, product wrapper | **219** in **166 files** |
| with `title=` | **174** (36 of them a composed node) |
| with `action=` | **34** |
| card-links (`to` / `onClick`) | **30** |
| `<Card>` sites using MUI's Card, out of scope | 3 in 1 file (`StixDomainObjectAuthorKnowledge.jsx`) |

> **Do not "re-correct" these figures. Re-run the counter instead.**
> `node fds-migration/scripts/count-surfaces.mjs` prints every number in this
> table, and it is the only method that counts.
>
> Four wrong figures circulated before it existed, each from a different shortcut,
> named here so none is restored. **222 / 167** counted every `<Card>` tag in the
> front, mixing in the 3 MUI sites — 219 + 3 = 222, 166 + 1 = 167. **216 / 163**
> came from an import filter that recognised only long paths and missed three
> relative `'./Card'` imports (`CardAccordion.tsx`, `CardNumber.tsx`,
> `CardStatistic.tsx`). **123** came from a line grep blind to multi-line opening
> tags: it missed 51. And **21 surfaces** for the Paper perimeter was a
> hand-maintained tally, not a count — see §2.

**`title`/`action` and the Card wave are one decision, not two.** 174 of the 219
sites pass `title=`, and the library title row cannot follow the host's text
colour (`LIBRARY-FEEDBACK.md` #37). The day that colour is reachable, 174 sites
become expressible in one move.

---

## 7. Measurement lessons

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
