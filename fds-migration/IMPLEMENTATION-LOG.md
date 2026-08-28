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

### Custom-theme iso-functionality, proved without a database

The requirement is that a platform administrator's custom theme keeps working
identically. That is testable without a running instance, because the mechanism
is a pure one: `AppThemeProvider` passes the DB's `Theme.theme_*` fields into
`ThemeDark()` / `ThemeLight()` as parameters, and the FDS constants are only the
fallback when a field is null.

So both theme modules were bundled at the old and the new bridge and called
twice each — once with a full set of custom values standing in for a DB theme
row (`background`, `paper`, `nav` i.e. `theme_nav`, `primary`, `secondary`,
`accent`, `text_color`), once with no arguments — and the resulting palettes
were diffed field by field.

| Palette | Fields | Changed |
| --- | --- | --- |
| Dark, custom theme | 116 | 11 |
| Light, custom theme | 117 | 20 |
| Dark, standard theme | 116 | 13 |
| Light, standard theme | 117 | 21 |

**The custom theme is protected exactly where it should be.** The standard
palettes move on three fields the custom palettes do not: `primary.main` and
`border.primary` in dark, `secondary.main` in light. Those are precisely the
DB-overridable fields whose FDS fallback changed — under a custom theme they
keep the administrator's value, untouched by this pass.

**`theme_nav` does not appear in any of the four diffs.** The top bar's colour
is byte-identical before and after, in both modes, custom or standard.

Everything that does move is a field with no DB override — `error`, `warn`,
`success`, `dangerZone`, `severity` and the `designSystem` block — which is the
set `migration-state.json` already documents as visually live. Those are the
deltas for design to validate; they are not regressions but the WCAG and Figma
decisions the library already shipped, finally reaching this product's MUI
theme.

What this method does **not** cover, and what still needs a running instance: the
`Navbar` accent under a custom `theme_primary` (workaround #1 resolves it at
render time from `theme.palette.primary.main`, so it follows the same parameter
and is expected to be iso-functional, but it is not proved here), and the
`color-mix` derivatives of a custom accent — see the #6 measurement above, which
is why that workaround stays.

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

## 2026-08-11 — Admin top bar adopts the design-system `Header`

Branch: `fds/header-pilot` (targets `design-system/current`). Pin unchanged at
`5960966216533f620393a2174213c666f57af7dd` — the token pass already installed
the `Header`, so this pilot bumps nothing.

### What the bar was

`AppBar` + `Toolbar`, painted by a gradient assembled from
`theme.palette.background.gradient.start/end` — which trace to the DB's
`theme_background`, **not** `theme_nav`. `theme_nav` reached this bar through
exactly one path: the Suspense fallback's `makeStyles` class. The bar already
supplied its own fixing, rail offset and three stacked banner offsets, and
pre-multiplied its own transparency at 90%.

### What changed

`Header` / `HeaderGroup` replace `AppBar` / `Toolbar`. The glass now comes from
the library at Figma's 94%, so the product's gradient stops became opaque —
keeping them pre-multiplied would have applied the transparency twice.

The assembled gradient is re-declared on the bar element. Measured under a
custom theme: the bar's `--gradient-default` carries the administrator's
`theme_background`, while the Navbar's still resolves to the library default —
the override does not leak, which is what a `:root` declaration would have
broken.

The search input is the library's `SearchField`, and the window moves from
550–680px to 200–500px as named constants on the group the product owns.

Height has one source of truth: `--fds-header-height` with the library's 68px
fallback, read by the chatbot offset. `WorkspaceTurnToContainerDialog.tsx`'s
`top: 68` was left alone — it positions a control inside a dialog and is not
this bar's height.

Per arbitration, the Suspense fallback keeps its `background.nav` paint
unchanged. This pilot normalises nothing there.

### What the adoption cost

Three affordances of the old field have no equivalent in `SearchField`: the
animated gradient border, the AI-tinted magnifier, and the loader inside the
field. The loader moved beside the field; the other two are gone. NLQ mode stays
readable from its toggle, which carries an always-AI-coloured glyph plus an
AI-tinted background and border when active. Filed as entry 20.

Eight compensations, entries 13–20. Entries 13, 14, 15, 16, 17 and 18 restate
gaps the OpenAEV Header pilot already filed — two consumers, not one.

### Accepted at the checkpoint

At 768px with the rail expanded, the AI actions and the mode toggles overlap by
131px. The bar this replaces did not overlap, but ran 323px off-screen instead,
so the controls needed a horizontal page scroll to reach. Accepted as-is by
design, like the OpenAEV pilot's own 57px. Page-level horizontal scroll below
1400px is pre-existing — the previous bar scrolls identically.

The "EE" marker in the bar is now the library `Chip` with `tone="tonic"`, the
tone library PR #72 added for exactly this badge. The 26 other `EEChip` call
sites keep the legacy marker; converting them is its own change. The bar's chip
is decorative — a clickable `Chip` renders a `<button>`, which cannot nest
inside the Ask Ariane button — see entry 21.

The bar still shows two blues: library controls resolve
`--color-filigran-brand-primary` (#42caff) while the MUI survivors read
`theme.palette.primary.main`, which the database theme row pins to the pre-WCAG
#0fbcff. Fixed by a sister pull request that migrates the built-in theme rows,
so this pilot stays front-only.

### Pending at the next pin bump

The library is replacing `Chip`'s `tone` axis with `severity="ee"` and a new
visual (Figma node 2752:19169, EE row: opaque `--color-filigran-tonic-primary`
fill, `--text-negative-primary` label, `content-compact-bold`). At the next
bump, switch `tone="tonic"` to the new word in `EEChip.tsx` and re-checkpoint
the bar. The bar's marker stays decorative — a recorded decision, see
LIBRARY-FEEDBACK.md entry 21.

`ProductSwitcher` still clips product names: library PR #107 gave the rail's
labels an ellipsis and a tooltip but does not touch the switcher, so entry 23
remains open.

### Verification

Step 5b, against the library's documentation site at the same pin: 12 properties
compared, **0 differences**, glass included.

Suite under Node 22: build, `check-ts`, lint, `verify-translation` and 158 test
files / 1391 tests green; migration conformity 16 checks, 0 issues.

Eleven new tests. Key assertions mutation-tested — restoring the 550px floor,
replacing the height variable with a literal, painting the active link from a
hardcoded colour, dropping the active state, and moving the gradient to `:root`
each turn the suite red.

## Final bump — pin `7e7b417`, the four library deliverables

Four library pull requests landed together: `Badge` (#114), `Spinner` and
`ProgressBar` (#115), the gradient-text child fill (#116), and `HeaderGroup`'s
leading separator (#117). Each was verified **in the installed package**, not
from commit titles: the first, second and fourth as exported declarations in
`index.d.ts`, the third as `.text-gradient-*>*{-webkit-text-fill-color:
currentColor}` in the built `index.css`. The served bundle was then confirmed to
carry the same rule, and the listening PID's working directory confirmed which
checkout answers on 3010.

### The cluster separator

Figma's rule between the AI cluster and the actions cluster is now the library's
`separatorBefore`, and the hand-painted `<div role="separator">` is gone. The
bar models it as the library's own example does — the separated cluster nests
inside the one that precedes it — with the rule drawn only when an AI cluster is
actually there to be separated from.

Measured in the running product, on the three themes:

| | |
|---|---|
| Air before the rule | 16px |
| Air after the rule | 16px |
| Inside each cluster | 8px |
| Rule | 1px, `border-elevation-subtle` at 0.5 opacity, 36px tall |

The rule's colour follows the theme (`rgb(31,57,101)` dark, `rgb(202,203,206)`
light). Visual order is unchanged: search, mode toggles, Ask Ariane, import,
triggers, notifications, profile.

### The AI controls, and the trap under them

`AskArianeButton` and `CtemCommandCenterButton` are now the library `Button` and
`IconButton` in their `ia` variant. `UploadImport` moved to the library too, but
in the **default** variant: importing data is not an AI affordance, and giving
it the AI gradient would have been a visual decision nobody asked for.

The library hides a gradient label with `-webkit-text-fill-color` alone.
OpenCTI's `createTextGradientSx` also set `color: transparent`, and the two
together defeat the very reset that makes nested children visible: a child
asking for `currentColor` resolves it back to transparent. The product recipe
was aligned on the library's, red-before-fix.

Measured inside the gradient button, on all three themes — chip fill and
background, icon paint, and the loading spinner (forced on to observe it):
nothing nested renders invisible. The chip sits 8px from the label; with the
library button that distance is entirely the chip's own margin, because the
label is a bare text node and no flex gap falls between them.

### Progress

The bar's one MUI loader — the NLQ agents menu — is the library `Spinner`. It
carries a `label`, because that row has no visible text and the spinner is the
only thing saying anything is happening. It could not be exercised in the
browser here: the NLQ affordance needs XTM One configured, which this checkpoint
instance is not.

### The guard, rebuilt

The first guard listed allowed MUI *modules*, which is how `Stack` arrived under
an already-allowed `@mui/material`. The unit is now the **symbol**, across the
bar and the components it owns, and the failure message names what arrived.
Three mutations were run: a new icon symbol from the already-allowed
`@mui/icons-material`, `Stack` from `@mui/material`, and the separator reverted
to a styled div. All three turn the suite red; restored, it is green.

A second guard asserts on the **rendered DOM**. It covers `UploadImport`, the one
bar control that also serves three screens the bar does not own — and it earned
its place immediately by catching a real regression: a library `Tooltip` throws
without a `TooltipProvider`, and only the bar had one. Fixed by providing once at
the private app's root. The other bar controls need the chatbot context and Relay
data; mocking half the application to reach a green would prove the mock, so they
stay on the source guard and on the measured checkpoint.

### What is still MUI, and why

Rendered in the bar: `ToggleButtonGroup`, `ToggleButton` and their `ButtonBase`
— the library ships no segmented control (LIBRARY-FEEDBACK #24) — plus
`MuiSvgIcon` glyphs, the library shipping no icon set. The navigation bar renders
glyphs and nothing else.

### Verification

`check-ts`, lint, `verify-translation` and the full test suite under Node 22.
Two new translation keys, declared in all nine locales.

## Second bump — pin `35a4768`, and the one gap that stays

Library PRs #118 (ProgressBar tones) and #119 (Spinner's 32px tier, Badge
default tone) landed on top of the four already consumed.

The five deliverables were verified on the **rendered build**, through a
throwaway probe mounted behind a URL flag and removed before commit — not from
the type declarations, which had already once described something the build did
not carry:

| | Measured in the browser |
|---|---|
| Spinner tiers | sm 16px, md 20px, lg 24px, **xl 32px**, all animating |
| Badge default | red — counter `rgb(136,17,6)`, dot `rgb(241,67,55)` |
| Badge `tone="brand"` | `rgb(66,202,255)` |
| ProgressBar `tone="success"` | fill `rgb(23,171,31)`, `role="progressbar"` |
| `separatorBefore` | rule drawn, 16px of air each side |
| Gradient child reset | present in the served CSS |

### The loader's tier, chosen by measurement

The NLQ menu's other rows render `FiligranIcon size="small"` in the same icon
slot; measured, that is **20×20**, which is the library's `md`. The 32px `xl`
tier is for a ring that has to encircle something, and this spinner encircles
nothing — it occupies the slot alone. A test fails if the tier is changed
without the slot changing.

### The badge went red without the product asking

The bar's unread marker passes no `tone`, so #119's new default repainted it
from brand blue to red. The product takes the library's default rather than
pinning the old look, and a test now fails if a `tone` is ever set silently —
choosing to override is a design decision and has to be written down when it is
made. Plates on the three themes are in the pull request.

### The coverage rule is not met, and it is one component

The bar still renders `ToggleButtonGroup`, `ToggleButton` and their `ButtonBase`.
That same gap blocks a second conversion: the NLQ dropdown *does* have a library
equivalent, but its trigger is a caret `<span>` inside a `ToggleButton`, so a
Radix trigger would either clone onto a non-focusable span or nest a button
inside a button. Neither is a conversion, so nothing was forced.

Everything else in the bar and the whole navigation bar are library components,
apart from `MuiSvgIcon` glyphs. The measured spec for the missing control is in
LIBRARY-FEEDBACK entry 24.

### One MUI family was still rendering, and the guard could not see it

The sentence above was not yet true when it was written. A sweep of the
**rendered** bar in a browser, at the served pin, on the three themes, found
`MuiStack-` inside the NLQ toggle — a `Stack` and a `Box` doing pure layout
inside the one MUI control the bar is allowed to keep. The guard already listed
`MuiStack-` as retired, but it read only the five files the bar owns, and this
one lives in `SearchInput.jsx`.

Both are now plain elements at the same geometry: the caret keeps its 4px
margin, its 4px padding and its 1px divider, and the toggle's box is unchanged
at 36 × 36px. `SearchInput.jsx` joined the by-symbol check, with the segmented
control's own symbols — `ToggleButtonGroup`, `ToggleButton`, `Tooltip`, `Menu`,
`MenuItem`, `ListItemIcon`, `ListItemText` — declared as the exemption and
nothing else. Putting `Stack` back turns the suite red; so does adding any
symbol from a module that is already allowed.

`Tooltip` is in that list on evidence, not convenience: MUI's group injects
`value` and `selected` into its children *through* the tooltip — measured,
`data-mui-internal-clone-element` on the wrapper and `Mui-selected` arriving on
the toggle. A library `Tooltip` is not in that cloning contract, so swapping it
would break selection while looking correct in a screenshot.

After the change the rendered bar carries, on all three themes: `MuiSvgIcon`
(glyphs), and `MuiToggleButtonGroup` / `MuiToggleButton` / `MuiButtonBase` —
the exempted control and the base class it renders. Nothing else.

### The token bridge was stale, and CI could not say so

`check-fds-conformity.mjs` reported **16 checks, 0 issues** on this branch
throughout. Run with the library actually checked out beside the product, the
same script reports `bridge-freshness: STALE`: `theme.css` moved between
`990810f` and `35a4768` and the bridge was never regenerated. The gate had been
returning `SKIPPED` — counted inside the 16 — because CI has no sibling
checkout, so a green line was standing in for a check that never ran.

The change itself is harmless, and that was established before touching
anything: 620 custom properties on each side, **not one value different**. What
moved is the four `.text-gradient-*` utilities, which are rules, not tokens —
library PR #116, the very fix this bump came for.

The bridge was regenerated with the library's own generator
(`pnpm generate:mui-bridge --product opencti --write-to-product`), never edited
by hand, and the result is a two-line diff: the recorded `theme.css` hash and
the file's own checksum. Conformity is now 16 checks, 0 issues with
`bridge-freshness` genuinely **OK** rather than skipped.

### R3 re-measured in the computed accessibility tree, and it was red

"Present in the DOM" was doing the work of "announced". Read through CDP
(`Accessibility.getPartialAXTree` on the anchor itself, the OpenAEV method),
the Notifications control was, on all three themes:

| | before | after |
|---|---|---|
| role | `link` | `link` |
| NAME | `"Notifications"` (`aria-label`) | `"Notifications"` (`aria-label`) |
| DESCRIPTION | **`""`** | **`"5 unread"`** |
| `aria-describedby` | on the `<svg>`, inside `aria-hidden` | on the `<a>` |

The badge was wrapping the glyph. `TopBarIconLink` renders the glyph inside
`aria-hidden="true"` — as `IconButton` does — so the reference `Badge` clones
onto its child landed outside the accessibility tree. A DOM sweep found the
text and read as a pass; the computed tree said nothing was announced.

The badge now marks the **control**: `TopBarIconLink` takes a `badge` prop and
wraps its own anchor. No `tone` at any point on that path — red is the library
default and the decision (Sandy, 2026-08-14), on both products.

Two further defects fell out of the same pass, neither of them visible in the
markup:

- The **tooltips on Triggers and Notifications never opened**, on pointer or on
  keyboard. `TopBarIconLink` named the five props it knew about, so everything
  `TooltipTrigger asChild` cloned onto it — handlers, `data-state`, ref — was
  dropped. The tooltip on the library `IconButton` beside them worked, which is
  what made the gap invisible. Fixed by forwarding the ref and the rest props.
- Doing that naively then **shrank the control to 24×28** instead of 36×36: a
  cloning parent passes `className: undefined`, and spreading it replaced the
  library variant wholesale. `className` and `style` are merged now, with a
  test that fails if either is spread again.

Both are filed as LIBRARY-FEEDBACK 28 and 29. Re-checkpointed after the change:
MUI families unchanged (glyphs plus the exempted segmented control), separator
16px|16px with 8px inside each cluster, EE chip legible at rest and on hover in
the three themes, badge dot 8px red (`rgb(241,67,55)` dark, `rgb(184,24,10)`
light), and all three tooltips opening on pointer and on keyboard.

## Reconciliation of the two review passes

Two sessions worked these reserves in parallel and both pushed. Sandy arbitrated
the outcome: **the encapsulated design is the one that ships** — the control
owns its own marker through a `badge` prop, forwards its ref and rest props, and
merges `className`/`style`. Everything above stands as written.

Two things were grafted onto it from the other pass, and nothing else:

**A counter-check on the accessible tree.** `TopBarIconLink.test.tsx` proves the
COMPONENT honours its contract. `TopBarNotifications.a11y.test.tsx` proves the
BAR'S CALL SITE passes the right thing — the control composed exactly as
`TopBar` composes it, inside a tooltip trigger, with the badge props the bar
supplies. The defect was never in the component's contract; it was in what the
bar handed it. The two files also compute the tree by different routes —
`dom-accessibility-api` directly here, jest-dom's matchers there — so they
cannot both go green for a reason belonging to one shared helper. Mutation-
tested: moving the badge back inside the `aria-hidden` glyph turns **both**
files red, four assertions in total.

**The exemption list cannot grow by accretion.** The two exemptions are
re-confirmed and dated 2026-08-14, with the retirement condition spelled out —
the library ships the component. A new test walks every entry and fails if one
carries a reason that is neither of the two Sandy granted. Mutation-tested:
adding a third with an invented justification turns the suite red, naming the
symbol.

Both grafts are test-only. The rendered bar at this head is identical to the one
measured above, so the checkpoint was not re-run: there is nothing new to look
at, and re-photographing an unchanged bar would only look like evidence.

## 2026-08-26 — Fonts were never loading, and it was the bench, not the components

Reported as "the fonts look broken on ALL library components". The "all at once"
was the tell, and it pointed at the environment, same family as L116 (a stale
`dist`). It was broader than reported: **nothing in the app rendered in IBM Plex
Sans — MUI components included.**

**Measured before touching anything.** The declared `font-family` resolved to
`"IBM Plex Sans"` on every element sampled, library and MUI alike, which is why
reading the computed family alone says nothing. The decisive probe is whether
the face is USED:

| probe | before | after |
|---|---|---|
| `document.fonts.check('400 14px "IBM Plex Sans"')` | `false` | `true` |
| canvas width of a fixed string in Plex | 309.31 | **339.14** |
| same string in a deliberately bogus family | 309.31 | 309.31 |
| face statuses | `error` / `unloaded` | `loaded` |

Before, Plex measured **identical to a nonexistent font** — proof of silent
fallback to the default serif. Every screenshot in this round had been serif and
nobody, including me, had questioned it.

**Root cause.** This worktree runs on a SHADOW `node_modules` whose entries are
symlinks into `~/dev/paper-cti`. Vite resolves symlinks to their real path, so
`@fontsource`'s woff2 files behind the `@font-face` rules were requested through
the `/@fs/` escape hatch at a real path OUTSIDE the project root, and
`server.fs.allow` denied them — **HTTP 403**, verified by curl.

**Fix — environment only, no product code.** `@fontsource` was made a real
directory inside the worktree instead of a symlink out (4.7 MB), so the resolved
path falls inside the root and Vite serves it: 403 -> 200. A first attempt went
through an uncommitted Vite config override widening `fs.allow`; it lost the base
config's plugins and broke `vite-plugin-relay` ("graphql: Unexpected invocation
at runtime"), so it was abandoned rather than patched — moving the file was the
smaller change.

**Lesson, extending L116.** The pre-judgement probe must cover FONTS, not just
colour tokens. And the probe is not "what does `font-family` compute to" — a
missing face leaves the declaration intact and lies. It is `document.fonts.check`
plus a width comparison against a bogus family. A shadow `node_modules` makes
every symlinked ASSET a candidate for the same 403, not only fonts.

## 2026-08-26 — Two ways a pointer proof can lie about geometry

Both cost real time today and both produced FALSE NEGATIVES: I concluded three
times that a click "did nothing" when the click had never reached its target.

**1. A plausible viewport can still be the wrong coordinate space.** The known
lesson is "hidden panel = 0x0 viewport = invalid geometry, check before each
series". Today the viewport read a perfectly healthy `1440x900` and was still
unusable, because the real browser window was `400x250`:

    innerWidth/innerHeight  1440 x 900      <- emulated, what every rect() uses
    outerWidth/outerHeight   400 x 250      <- real window, what the pointer uses

Every click beyond ~400x250 CSS px landed on `<html>`. Screenshots looked
complete, `getBoundingClientRect` was consistent, `elementFromPoint` said the
target was hittable — and the click still missed. Three separate "defects" I had
started diagnosing (an Integrations card menu that would not open, a Retention
create button that would not open, a converted Select that would not open) were
all this one artefact. At `1280x800` all three work.

**The check is therefore not `innerWidth > 0`.** It is:

    innerWidth === outerWidth  (or a known, tested ratio)

and, once per series, a positive control: install a capturing `click` listener,
click a known element, and assert `event.target` is that element. If the target
comes back as `HTML`, stop — the pointer is lying, nothing measured after that
point means anything.

**2. An option's own rect can be on-screen and still be clipped.** Filtering
options by their own `getBoundingClientRect()` against the viewport is not
enough. The library Select panel is `max-h-40` (160px) with an internal
`overflow-y: auto`, so with 82 entity types most options have rects that sit
inside the window while being clipped by their scroll parent:

    option    (344, 149, 183, 32)   <- on screen by its own rect
    scroll vp (344, 437, 183, 160)  <- but the container starts 288px lower

`elementFromPoint` correctly returned `HTML` there, and it was right. Visibility
of an option must be its rect INTERSECTED with the scroll container's rect. That
intersection test is what finally produced the proof.

Corollary, recorded because I asserted the opposite for a while: a synthetic
`element.click()` succeeding where a real pointer fails proves nothing about the
product. It only proves the handler exists. Radix Select opens on `pointerdown`
and a synthetic click takes the `onClick` path, so the two disagree by design.

## 2026-08-29 — A wrapper cannot see what the call site wrote

The button wrappers decide per render whether the library can reproduce a site.
That works for everything the props say, and fails for one thing they cannot:
whether `color` was a literal or an expression. A wrapper is a runtime
component; `color={copied ? 'success' : 'primary'}` reaches it as `'success'`.

It matters because a control that changes engine between renders is remounted,
and a remount at the moment of activation takes the keyboard focus with it. The
ruling was identity stability over partial conversion, so the 20 dynamic-colour
sites carry `keepMui` and stay on MUI for their whole life.

`keepMui` is therefore load-bearing and entirely conventional: nothing stops a
new site from writing `color={cond ? 'a' : 'b'}` without it, and the failure is
invisible — the control simply swaps engine on interaction.

**Candidate check for a follow-up wave:** fail when a wrapper `Button` or
`IconButton` has a non-literal `color` (or `variant`/`intent`) and no `keepMui`.
It is a static rule, which is exactly the level the information exists at — the
same reason `check-accessible-names.mjs` had to be static. The sweep that found
the 20 sites is the rule already; it needs turning into a gate, not inventing.
