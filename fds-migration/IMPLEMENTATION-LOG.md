# Implementation Log — OpenCTI

Append-only session journal — never rewrite a previous entry, only add new
ones at the bottom. One entry per work session: date, what changed, why,
and any friction that should feed back into the process (prompts/scripts
in filigran-design-system).

## Log format

```
### YYYY-MM-DD — <short summary>
- Branch: fds/...
- Changed: <files>
- Friction / process feedback: <none, or what to fix upstream>
```

---

### 2026-08-04 — Left navigation replaced by the design-system `Navbar`
- Branch: fds-navbar (targets `design-system/current`)
- Pin: `56f7e59823cae7d815a451206e3cb4cb1d31022d` (head of the library's `main`)
- Changed:
  - Added `opencti-front/src/private/components/nav/`: `NavBar.tsx`
    (data component + exported pure `NavBarView`), `useNavMenu.tsx` (typed,
    fully filtered menu tree + pure `filterNavGroups`), `navBarConstants.ts`
    (rail widths, storage keys, persistence helpers), and their tests.
  - Deleted `LeftBar.jsx`, `LeftBarItem.tsx`, `LeftBarHeader.tsx`.
  - Retargeted the seven components importing the rail widths, and the
    end-to-end page object, onto the new modules.
  - Containerised authentication for the private library: three Dockerfiles,
    one composite action and six workflows.
  - `useFdsThemeScope` reshaped to write the design-system theme class on the
    document root (the library portals flyouts and tooltips to `document.body`,
    so a subtree-scoped class would leave them unthemed).
- Friction / process feedback: recorded in `LIBRARY-FEEDBACK.md` (five
  library entries) and reported separately as playbook corrections.

#### Pre-existing issues found, dated and deliberately NOT fixed here

This pull request is mono-subject. The following were found while working on
the navigation, are older than this change, and are left untouched.

- **2026-08-04 — Two components read the collapsed-rail flag without
  subscribing to the toggle channel.**
  `opencti-front/src/components/graph/GraphToolbar.tsx` (line 32) and
  `opencti-front/src/private/components/data/ToolBar.jsx` (line 69) read
  `localStorage.getItem('navOpen')` during render but never subscribe to
  `MESSAGING$.toggleNav`, unlike the eight other readers. Their left offset is
  therefore stale until the next re-render for another reason: collapse the
  rail with a graph open and the graph toolbar stays offset for the old width.
  Pre-dates this change — the previous rail emitted the same notification.
  Fix belongs in its own pull request: subscribe like the other eight, or
  extract a shared `useNavOpen()` hook and use it in all ten places.

- **2026-08-04 — `yarn i18n-checker` is declared but cannot run.**
  `opencti-front/package.json` declares the `i18n-checker` script, but
  `i18n-checker.js` does not exist anywhere in the repository and no
  continuous-integration job invokes it. Locale drift is therefore unchecked.
  Flagged for the OpenCTI team: either restore the script and wire it into
  the front-end quality workflow, or drop the dead entry. The nine locale
  files were verified symmetric by hand for this change (5384 keys each).

- **2026-08-04 — `Backend / Integration tests` is flaky on this branch.**
  Two continuous-integration runs on the same commit `e85be9fa79` disagree:
  run 30958977348 green, run 30958981411 red. This change touches no back-end
  file. Dated here rather than investigated: it is not this pull request's
  subject.

### 2026-08-05 — Four checkpoint findings from the running product

Reported after a hands-on pass on the running platform. Each is stated with its
diagnosis and its category (host style, product code, or library gap).

1. **The rail was neither full height nor fixed** — host layout. The library's
   `<nav>` is laid out in flow and sized with `h-full`; OpenCTI's shell has no
   definite height, so the rail measured 776px in an 800px viewport and scrolled
   away with the page. The MUI Drawer it replaces was fixed-positioned. Restored
   with the OpenAEV pilot's own recipe: `position: sticky`, `top` at the banner
   offset, `align-self: flex-start` and a height of `100dvh` minus the banners.
   Filed as observation 11 in `LIBRARY-FEEDBACK.md` — two consumers out of two
   had to write the same block.

2. **The "Made by Filigran" signature was mis-sized, and showed the wordmark
   when collapsed** — product code. The replaced footer used a `div` with an
   `.app-navbar-made-by` class that matches no rule anywhere: OpenCTI has no
   Tailwind build, so only the utilities the design system itself emits exist at
   runtime. Rewritten as `MadeByFiligran.tsx`, ported from the OpenAEV pilot:
   inline geometry, library caption tokens for the label, and — collapsed — a
   12×12 box with `object-fit: cover` and a left origin, which crops the
   wordmark down to the Filigran emblem alone. One asset, one accessible name
   (`alt="Filigran"`) in both states. Non-interactive, exactly like the row it
   replaces.

3. **Collapsed, hovering from one submenu row to the next opened nothing** —
   library behaviour, compensated in the product. Reproduced deterministically:
   the first hovered row opens its flyout, every subsequent hover opens and
   immediately closes, and `localStorage.selectedMenu` ends up emptied. Cause:
   collapsed, the library drives the hover flyout from the same
   `open`/`onOpenChange` pair as the expanded accordion, and its 150 ms delayed
   close of the previous row resolves against the same state snapshot as the
   next row's open. The product now passes those props only when expanded.
   Filed as entry 10 in `LIBRARY-FEEDBACK.md`, with its removal test.

4. **A pre-existing trap, dated and NOT fixed here: `bannerHeight` is the
   unitless string `'0'`.** `private/Root.tsx` builds
   `bannerHeight = bannerHeightNumber !== 0 ? `${n}px` : '0'`. Any `calc()`
   containing it is therefore invalid CSS when no banner is displayed, and an
   invalid declaration is dropped in silence — including OpenCTI's own
   `marginTop: calc(${topBannerHeight}px + ${bannerHeight})` in
   `private/Index.tsx`, which is how this rail first lost its offsets. The rail
   now derives its offsets from `bannerHeightNumber` instead. The shell's own
   declaration is left alone: it is not this pull request's subject. Fix
   belongs in its own change — make the `'0'` branch return `'0px'`.

### 2026-08-05 — Independent review convergence (two defects fixed, one dated)

Findings of an independent review of this pull request at
`d4688bba9d43fa764f66c0663dc5014370e8790b`, fixed on the same branch.

1. **An image-build entry point was left without the BuildKit secret** — CI
   wiring, fixed. `.github/workflows/ci-docker-build.yml` builds the whole
   `opencti-platform/Dockerfile` (no `target:`, so it reaches `builder-front`
   and its `RUN --mount=type=secret,id=fds_git_token`) and passed no `secrets:`
   to `docker/build-push-action`. An unprovided BuildKit secret is not an empty
   file, it is no file, so the step dies on `can't open
   /run/secrets/fds_git_token: No such file or directory` — reproduced locally
   on a two-line Dockerfile. Its three callers are `deploy-design-system.yml`
   (**push to `design-system/current`**, i.e. this pull request's own target
   branch), `deploy-testing-xtm-one.yml` and `test-feature-branch.yml`, none of
   which run on a pull request, which is why every check here is green. Fixed,
   and `opencti-front/src/ciDesignSystemSecret.test.ts` now performs the
   enumeration instead of a human: every `docker/build-push-action` step whose
   Dockerfile requires the secret, and which does not stop at an earlier
   `target:`, must declare it.

2. **A navigation parent whose submenu was emptied by permissions disappeared**
   — iso-functionality, fixed. `filterNavGroups` removed such a parent; the
   component it replaces rendered it as a plain navigable row (`LeftBarItem`'s
   `hasSubItems === false` branch). Two reachable cases: a user granted only
   `INGESTION` satisfies `canSeeData` but none of the eight `Data` sub-item
   grants and lost `/dashboard/data`; hiding the `Dashboard` entity type empties
   the `Dashboards` submenu and lost `/dashboard/workspaces/dashboards`.
   `NavBar.renderItem` already rendered an empty `subItems` as a leaf, so the
   fix is to stop dropping the row. Covered in `useNavMenu.test.tsx` and
   `NavBar.test.tsx`.

#### Pre-existing issue found, dated and deliberately NOT fixed here

- **2026-08-05 — Layout offsets computed from the old 55px rail.** The rail is
  48px collapsed since this change, and the constants in `navBarConstants.ts`
  follow, but three files hardcode the old geometry instead of importing them:
  `attack_patterns_matrix/AttackPatternsMatrixColumns.tsx` (`BASE_WIDTH: 110`
  and `NAV_WIDTH: 125` — the pair encodes 55 collapsed / 180 expanded, so the
  collapsed offset is now 7px too wide), and the `calc(100vw - 455px)` /
  `calc(100vw - 580px)` families in
  `common/stix_core_objects/StixCoreObjectContent.jsx` and
  `StixCoreObjectMappableContent.tsx` (same 125px delta, same 7px collapsed
  error). Cosmetic, not functional, and the magic numbers pre-date this change.
  Fix belongs in its own change: import `SMALL_BAR_WIDTH` / `OPEN_BAR_WIDTH`
  instead of restating them.

## 2026-08-06 — library pin bumped to `486cec92c3ab`

Bumped `@filigran/design-system` from `56f7e59823ca` to `486cec92c3ab`, the head
of the library's `main`. Four commits: `Menu` sub-menu primitives with
`ProductSwitcher` adopting them (#81), a docs `/status` correction (#83), the
pointer-cursor fix on rail rows (#84), and the new `Header` component (#85).

**What the bump fixed, measured in the running platform.** Before it, every
button-rendered row of the rail resolved to `cursor: default` — 14 of them in
the expanded rail, 1 in the collapsed one — while link rows had the hand cursor
for free from the UA sheet. After it, 13/14 and 1/1. **This pilot had not
reported that regression**; the OpenAEV pilot had, and PR #84 credits it. It was
shipped here unnoticed for the same reason the four checkpoint findings were:
the parity pass compared structure and geometry, never pointer affordance.

**What the bump did not fix.** The `ProductSwitcher` trigger is not a
`NavbarItem`, so it keeps `cursor: default`. Filed as entry 12 in
`LIBRARY-FEEDBACK.md`. Deliberately **not** compensated product-side: a host
rule would hide the gap from every other consumer.

**Compensations re-checked, none retired.** `Navbar.tsx` and `NavbarSubmenu.tsx`
are byte-identical between the two pins — only `NavbarItem.tsx` changed — so the
removal conditions of compensations 1 (accent), 2 and 3 (`asChild`), 4 (shared
`open` prop), 5 (flow layout), 6 (`shrink-0`) and 7 (portal z-index) are all
still unmet. `NavbarProps` still exposes no accent prop; `NavbarSubmenuProps`
still exposes a single `open`/`onOpenChange` pair.

**Nothing my rail depends on moved.** Set-diffing the compiled `dist/index.css`
between the two pins: 641 → 689 class selectors and 414 → 420 custom properties,
with **zero removals** on either. The accent guard in `NavBar.test.tsx`, which
reads the installed stylesheet, therefore still passes — as does the whole
nav-scoped suite (41 tests) and `tsc`/`lint`.

**One intentional visual change, inside the product dropdown.** `#81` moved
`ProductSwitcher`'s panel onto `Menu`: row padding-right 8px → 16px, panel
min-width 192px → 200px with a new 300px cap and a bounded max-height, divider
margin 2px → 4px, group header band 24px → 32px, and disabled rows painted with
the disabled tokens instead of `opacity-60`. Row height (36px) and label size
(14px) are unchanged — verified in the running platform. Accepted as-is: it is a
checkpointed library decision, not drift.

**Package size: the expected reduction did not happen, and could not have.**
The install grew from 3 384 759 to 3 637 106 bytes (+252 347, +7.5%); the
downloaded cache archive grew from 3 388 999 to 3 641 346 bytes (+252 347,
+7.4%; the cache holds two archives of the old build whose entries are
byte-identical and whose sizes differ by 92 bytes of archive metadata, so read
that figure ±92). The package has shipped `files: ["dist"]` since the initial monorepo
scaffold, which is an ancestor of both pins, so the documentation was never in
the tarball to begin with — the 12 packed files are `dist` plus `README`,
`CHANGELOG` and `package.json`. The growth is `Header` and the `Menu`
primitives, and it is almost entirely source maps and typings: `index.js.map`
+76 160 and `index.mjs.map` +75 315 bytes together account for 60% of it.
