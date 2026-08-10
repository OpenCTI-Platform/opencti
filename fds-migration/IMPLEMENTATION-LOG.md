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

## 2026-08-11 — Token pass: pin bumped to `5960966`, bridge regenerated

Branch: `fds/token-bridge-bump` (targets `design-system/current`).
Pin: `486cec92c3abf006997ac269d34ff0fcc23f178f` → `5960966216533f620393a2174213c666f57af7dd`
(13 library commits). The bump was pushed and proved green on its own
(17/17 jobs) before anything else was committed on top of it.

### The bump brought no token, and that is the point

`theme.css` is **byte-identical** at the old and the new pin. Every token change
below was already inside the pin OpenCTI had installed since 2026-08-06; what
was stale was the bridge, generated from the `theme.css` of **2026-07-16**
(library commit `f3dcda7`, #32). Twelve library commits of token changes had
accumulated behind it. The product was therefore running a MUI theme built from
July values against a library stylesheet shipping August ones.

`migration-state.json` had recorded that lag as a false positive of the
freshness check. It was not. The note is corrected in the same commit.

### Method — and why it is worth reusing at every bump

A plain diff of the old and the new bridge cannot tell a token change apart from
a generator change. So the bridge was regenerated **at every version of
`theme.css` in `main`'s history** since the one it was built from — twelve runs,
same generator throughout — which separates the two cleanly:

| Contribution | Tokens moved |
| --- | --- |
| Generator alone (same `theme.css`) | **0** — one JSDoc comment reflowed |
| `theme.css` alone (same generator) | **96 changed, 45 added, 2 removed** |

The final run is byte-identical to the committed bridge, so the attribution
chain is proved end to end rather than asserted. Each row below names the
library commit whose `theme.css` moved that value, and the OpenCTI MUI theme
keys that read it — "no key" means the token is in the bridge but this product
consumes nothing from it, so the change is invisible here.

**Of the 143 tokens that move, 17 are consumed by this product.** Those 17 are
listed first.

### Removed tokens

`--radius-xs` (`2px`) and `--shadow-xs` (`2px`), both dropped by the library's
`feat(tokens)!` #49. Neither is consumed by `ThemeDark.ts` or `ThemeLight.ts`,
so the breaking change is inert here.

### Value changes, token by token

| Token | Mode | Old → new | Library commit(s) | OpenCTI MUI theme keys |
| --- | --- | --- | --- | --- |
| `--bg-elevation-disabled` | dark | `#18191b` → `#101b33` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `dark:palette.designSystem.background.disabled` |
| `--border-elevation-default` | dark | `#3665b4` → `#3a5bbb` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `dark:palette.designSystem.border.main` |
| `--color-feedback-error-tertiary` | dark | `#f8958c` → `#f57266` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `dark:palette.dangerZone.light`<br>`dark:palette.dangerZone.text`<br>`dark:palette.designSystem.destructive.light` |
| `--color-feedback-neutral-primary` | dark | `#7a9cd6` → `#95969d` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `dark:palette.severity.none`<br>`dark:palette.severity.default` |
| `--color-filigran-brand-primary` | dark | `#0fbcff` → `#42caff` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `dark:THEME_DARK_DEFAULT_PRIMARY`<br>`dark:palette.designSystem.primary.main` |
| `--color-filigran-brand-tertiary` | dark | `#009edb` → `#0079a8` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `dark:palette.designSystem.primary.dark` |
| `--color-feedback-error-primary` | light | `#e51e10` → `#b8180a` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37) | `light:palette.error.main`<br>`light:palette.dangerZone.main`<br>`light:palette.severity.critical`<br>`light:palette.designSystem.destructive.main`<br>`light:palette.designSystem.alert.error.primary` |
| `--color-feedback-error-secondary` | light | `#f8958c` → `#f57266` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37) | `light:palette.dangerZone.light`<br>`light:palette.designSystem.destructive.light`<br>`light:palette.designSystem.alert.error.secondary` |
| `--color-feedback-info-primary` | light | `#009edb` → `#0079a8` | b0b12eb feat(search-field): implement SearchField component (#41) | `light:palette.severity.info`<br>`light:palette.designSystem.alert.info.primary` |
| `--color-feedback-neutral-primary` | light | `#afb0b6` → `#62636a` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `light:palette.severity.none`<br>`light:palette.severity.default` |
| `--color-feedback-success-primary` | light | `#17ab1f` → `#117916` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `light:palette.success`<br>`light:palette.severity.low`<br>`light:palette.designSystem.alert.success.primary` |
| `--color-feedback-success-tertiary` | light | `#117916` → `#094e0b` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `light:palette.success`<br>`light:palette.designSystem.alert.success.tertiary` |
| `--color-filigran-tonic-primary` | light | `#00f0bc` → `#009474` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37)<br>b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `light:THEME_LIGHT_DEFAULT_SECONDARY`<br>`light:palette.designSystem.secondary.main` |
| `--gradient-default` | dark | `linear-gradient(135deg, #070d18 0.0%, #0c1527 100.0%)` → `linear-gradient(90deg, #070d18 0.0%, #0c1527 100.0%)` | 7ea6c51 feat(navbar): Navbar, NavbarItem, NavbarSubmenu, ProductSwitcher (#43) | `dark:palette.designSystem.gradient.background` |
| `--gradient-focus` | dark | `linear-gradient(90deg, #0fbcff 0.0%, #00f0bc 100.0%)` → `linear-gradient(90deg, #42caff 0.0%, #00f0bc 100.0%)` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `dark:palette.designSystem.gradient.focus` |
| `--gradient-default` | light | `linear-gradient(135deg, #f2f2f3 0.0%, #ffffff 100.0%)` → `linear-gradient(90deg, #f2f2f3 0.0%, #ffffff 100.0%)` | 7ea6c51 feat(navbar): Navbar, NavbarItem, NavbarSubmenu, ProductSwitcher (#43) | `light:palette.designSystem.gradient.background` |
| `--gradient-focus` | light | `linear-gradient(90deg, #0015a8 0.0%, #00f0bc 100.0%)` → `linear-gradient(90deg, #0015a8 0.0%, #009474 100.0%)` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37)<br>b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | `light:palette.designSystem.gradient.focus` |
| `--bg-elevation-disabled-layer-0` | dark | `#18191b` → `#101b33` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--bg-elevation-disabled-layer-1` | dark | `#313235` → `#13213e` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--bg-elevation-disabled-layer-2` | dark | `#313235` → `#13213e` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--bg-elevation-disabled-layer-3` | dark | `#313235` → `#13213e` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--bg-elevation-highlight` | dark | `#101b33` → `#13213e` | ff74716 feat(tokens)!: add overlay width + blur scale tokens, remove --shadow-xs (#49) | — |
| `--bg-elevation-highlight-layer-0` | dark | `#101b33` → `#13213e` | ff74716 feat(tokens)!: add overlay width + blur scale tokens, remove --shadow-xs (#49) | — |
| `--bg-elevation-highlight-layer-1` | dark | `#13213e` → `#182a4e` | ff74716 feat(tokens)!: add overlay width + blur scale tokens, remove --shadow-xs (#49) | — |
| `--bg-input-default` | dark | `#101b33` → `#13213e` | ff74716 feat(tokens)!: add overlay width + blur scale tokens, remove --shadow-xs (#49) | — |
| `--bg-input-disabled` | dark | `#18191b` → `#101b33` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--bg-input-hover` | dark | `#070d18` → `#0d172b` | d7ea4f2 feat(chip): add the tonic brand tone, and sync the Figma tokens it ships with (#72) | — |
| `--border-elevation-default-layer-0` | dark | `#3665b4` → `#3a5bbb` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--border-elevation-default-layer-2` | dark | `#c8d6ee` → `#7a9cd6` | ff74716 feat(tokens)!: add overlay width + blur scale tokens, remove --shadow-xs (#49) | — |
| `--border-elevation-default-layer-3` | dark | `#ffffff` → `#7a9cd6` | ff74716 feat(tokens)!: add overlay width + blur scale tokens, remove --shadow-xs (#49) | — |
| `--border-elevation-subtle-layer-2` | dark | `#3665b4` → `#2b4f8d` | ff74716 feat(tokens)!: add overlay width + blur scale tokens, remove --shadow-xs (#49) | — |
| `--border-elevation-subtle-layer-3` | dark | `#7a9cd6` → `#2b4f8d` | ff74716 feat(tokens)!: add overlay width + blur scale tokens, remove --shadow-xs (#49) | — |
| `--color-feedback-neutral-secondary` | dark | `#2b4f8d` → `#62636a` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--color-feedback-neutral-secondary-transparency` | dark | `#2b4f8d4d` → `#62636a4d` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--color-feedback-neutral-tertiary` | dark | `#c8d6ee` → `#cacbce` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--color-filigran-brand-primary-transparency` | dark | `#0fbcff1a` → `#42caff1a` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--icon-highlight` | dark | `#0fbcff` → `#42caff` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--bg-alert-error` | light | `#f8958c4d` → `#f572664d` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37) | — |
| `--bg-elevation-heading-layer-1` | light | `#f2f2f3` → `#f4f4f6` | d7ea4f2 feat(chip): add the tonic brand tone, and sync the Figma tokens it ships with (#72) | — |
| `--bg-elevation-heading-layer-2` | light | `#e4e5e7` → `#cacbce` | d7ea4f2 feat(chip): add the tonic brand tone, and sync the Figma tokens it ships with (#72) | — |
| `--bg-elevation-heading-layer-3` | light | `#cacbce` → `#afb0b6` | d7ea4f2 feat(chip): add the tonic brand tone, and sync the Figma tokens it ships with (#72) | — |
| `--bg-input-hover` | light | `#f2f2f3` → `#f4f4f6` | d7ea4f2 feat(chip): add the tonic brand tone, and sync the Figma tokens it ships with (#72) | — |
| `--border-alert-error` | light | `#e51e10` → `#b8180a` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37) | — |
| `--border-alert-info` | light | `#009edb` → `#0079a8` | b0b12eb feat(search-field): implement SearchField component (#41) | — |
| `--border-alert-success` | light | `#17ab1f` → `#117916` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--border-input-error` | light | `#e51e10` → `#b8180a` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37) | — |
| `--border-input-focus` | light | `#009edb` → `#0079a8` | b0b12eb feat(search-field): implement SearchField component (#41) | — |
| `--color-feedback-error-secondary-transparency` | light | `#f8958c4d` → `#f572664d` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37) | — |
| `--color-feedback-neutral-secondary` | light | `#f2f2f3` → `#95969d` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62)<br>e710971 feat(switch): land icon/Off tokens export and rebind off-thumb to dedicated token (#76) | — |
| `--color-feedback-neutral-secondary-transparency` | light | `#f2f2f34d` → `#95969d4d` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62)<br>e710971 feat(switch): land icon/Off tokens export and rebind off-thumb to dedicated token (#76) | — |
| `--color-feedback-neutral-tertiary` | light | `#62636a` → `#494a50` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--color-filigran-tonic-secondary` | light | `#009474` → `#005744` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37) | — |
| `--color-filigran-tonic-tertiary` | light | `#bdffed` → `#80ffdd` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37) | — |
| `--icon-error` | light | `#e51e10` → `#b8180a` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37) | — |
| `--icon-info` | light | `#009edb` → `#0079a8` | b0b12eb feat(search-field): implement SearchField component (#41) | — |
| `--icon-success` | light | `#17ab1f` → `#117916` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--text-input-error` | light | `#e51e10` → `#b8180a` | ab04390 feat(button): RFC-driven rework (variant × priority API) (#37) | — |
| `--grayblue-300` | both | `#3665b4` → `#3a5bbb` | b838d43 fix(tokens): WCAG 2.1 AA contrast remediation for interactive components (button, icon-button) (#62) | — |
| `--leading-content-base` | both | `115%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-content-base-bold` | both | `115%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-content-base-link` | both | `115%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-content-base-medium` | both | `115%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-content-button` | both | `115%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-content-caption` | both | `115%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-content-compact` | both | `115%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-content-compact-bold` | both | `115%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-content-compact-link` | both | `115%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-content-compact-medium` | both | `115%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-content-highlight` | both | `115%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-title-2xl` | both | `120%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-title-jumbo` | both | `120%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-title-lg` | both | `120%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-title-md` | both | `120%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-title-sm` | both | `120%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-title-xl` | both | `120%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--leading-title-xs` | both | `120%` → `150%` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-content-base` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-content-base-bold` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-content-base-link` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-content-base-medium` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-content-button` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-content-caption` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-content-compact` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-content-compact-bold` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-content-compact-link` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-content-compact-medium` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-content-highlight` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-normal` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-relaxed` | both | `1px` → `0.01em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-tight` | both | `0.5px` → `0.005em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-title-2xl` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-title-lg` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-title-md` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-title-sm` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-title-xl` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |
| `--tracking-title-xs` | both | `0.75px` → `0.0075em` | 179ee2e fix(tokens): correct systemic line-height and letter-spacing drift at the generator level (#67) | — |

### Added tokens (45 entries, 30 distinct)

None is consumed by this product's theme today; they are listed so a future
mapping pass can see what became available and when.

- `feat(tokens)!` #49 — `--blur-{sm,md,lg,xl}`, `--width-overlay-{sm,md,lg,xl}`, `--icon-subtle`
- WCAG #62 — `--color-feedback-contrast-{primary,secondary,tertiary}`, `--color-filigran-brand-primary-transparency-50`, `--icon-negative`, `--icon-neutral`, `--turquoise-750`
- `feat(chip)` #72 — `--bg-elevation-hover` and its four layers, `--color-filigran-tonic-accent`, `--color-filigran-tonic-accent-transparency-20`
- `feat(tokens)` #33 / `fix(tokens)` #67 — the `content-code` family (`--font-content-code`, `--font-mono-plex`, `--font-weight-content-code`, `--text-content-code`, `--leading-content-code`, `--tracking-content-code`)
- `feat(switch)` #76 — `--color-feedback-neutral-off`

Note `--color-filigran-brand-primary-transparency-50`: the product already
re-derives that exact token in `NavBar.tsx` (workaround #6). Its arrival in
`theme.css` does not retire that workaround — see below.

### Bump → retirement: what this bump let us delete

Every entry in `LIBRARY-FEEDBACK.md` was re-checked against the new pin's
source, one condition at a time.

**Retired.**

- **#5 — overlay stacking.** Library PR #96 routes all six floating surfaces
  through `var(--fds-z-overlay, 50)`. The host rule
  `body > [data-radix-popper-content-wrapper] { z-index: 1300 !important }` is
  replaced by `:root { --fds-z-overlay: 1300 }`. Proof, measured in the running
  product: the retired selector has 0 occurrences in the loaded stylesheets; the
  library's own compiled overlay class resolves to `1300`; unsetting the host
  variable drops it to the library default `50`.
- **#12 — `ProductSwitcher` pointer cursor.** Library PR #94 declares the cursor
  on the shared layers (`iconButtonVariants` covers the switcher's trigger).
  This pilot filed it instead of writing a host rule, so closing it deletes no
  product code — which is exactly the payoff of having filed it that way.

**Kept, with the condition that is still false.**

- **#1 — accent hook.** `NavbarProps` at the new pin still exposes no `accent`.
- **#2 / #7 — `asChild`.** `NavbarItem` still has no `href`/`to`, and no
  `NavbarItemBody` is exported, so a slotted row still loses the icon handling
  and the row body.
- **#3 — collapse label.** Still the literals `"Expand"` / `"Collapse"`.
- **#6 — derived brand tokens.** `theme.css` still declares
  `--color-filigran-brand-primary-transparency{,-50}` on the same root
  selectors as the base token, so a subtree override does not reach them.
  Measured in the running product: overriding the base to `#ff0000` on a
  subtree gives `rgb(255, 0, 0)` for the base and
  `color(srgb 0.258824 0.792157 1 / 0.1)` — i.e. the untouched root brand
  colour at 10 % — for the derivative. This is the trap that must be re-tested
  on every theme change, not the token alone.
- **#8 — rail width.** The `<nav>` still carries `w-45` with no `shrink-0`.
- **#9 — submenu role.** Flyout children are still `DropdownMenuPrimitive.Item`.
- **#10 — accordion vs flyout state.** Still a single `open`/`onOpenChange` pair.
- **#11 — rail layout.** The `<nav>` is still `h-full` in normal flow.

### Proposed as a standard playbook step

Steps 1 and the pin-bump exercise of `process/PRODUCT-IMPLEMENTATION-PLAYBOOK.md`
cover picking a pin and retiring compensations, but nothing there produces a
per-token account of what a bump changes and where it will show. The method
above is offered as that missing step: regenerate at every intermediate
`theme.css`, separate generator drift from token drift, attribute each value to
its originating commit, and join it against the product's own theme wiring so
the "where will this show" column is derived rather than guessed. Filed to the
library repository alongside this pass.

### Marker renamed: `FDS-WORKAROUND #1` → `FDS-CI-SECRET` in the CI wiring

The 2026-08-11 master sync added `FDS-WORKAROUND #1` markers to the five
workflow call sites that must forward `FDS_GIT_TOKEN`. That number was already
taken: `FDS-WORKAROUND #N` means `LIBRARY-FEEDBACK.md` entry N, and entry 1 is
the `Navbar` accent hook. Two unrelated things answered to the same label, in a
convention whose whole purpose is that a marker and its rationale cannot drift
apart. The CI markers are renamed `FDS-CI-SECRET`, which is not a library gap
and has no entry number.

**`FDS-CI-SECRET` — why those five lines exist.** A reusable workflow only sees
the secrets its caller hands it. Master's #17486 replaced `secrets: inherit`
with explicit mappings, which silently cut `FDS_GIT_TOKEN` off from
`ci-test-frontend-quality`, `ci-test-end-to-end`, `ci-license-check` and the two
`ci-docker-build` deploy callers. Master's explicit-secrets discipline is kept;
the token is declared in each reusable workflow's `workflow_call.secrets` and
mapped at each call site. `ciDesignSystemSecret.test.ts` enumerates both halves
of the call graph, so the next sync fails loudly — two of those five paths never
run on a pull request and would not otherwise show up red.
