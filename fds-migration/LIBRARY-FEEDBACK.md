# Library feedback — OpenCTI → filigran-design-system

Gaps and friction found while consuming `@filigran/design-system` in this
product. Nothing here is fixed library-side: per the migration contract a
missing or awkward library capability is reported, never forked or worked
around inside the library. Each entry states what the product needed, what the
library offers today, what the product did instead, and the concrete ask.

Every workaround in the code references this file by entry number, so the two
cannot drift apart.

Raised during: the navigation pilot (replacing `LeftBar.jsx` with `Navbar`),
library pin `56f7e59823cae7d815a451206e3cb4cb1d31022d`.

---

## 1. `Navbar` has no accent colour hook

**Needed.** OpenCTI lets a platform administrator set `theme_primary` in the
database, per theme. The selected navigation row has always been painted with
that colour, and inside a draft the whole rail switches its accent to the
warning colour to signal the draft context. Both are user-visible product
behaviour, not decoration.

**Today.** `NavbarItem` paints its `aria-current="page"` state from the fixed
brand token `--color-filigran-brand-primary`: a left border in that colour, and
a row tint derived from it through
`color-mix(in srgb, var(--color-filigran-brand-primary) 10%, transparent)`.
There is no prop, no CSS-variable contract and no documented override.

**Consequence.** The product sets that custom property inline on the `<nav>`
element, which recolours both utilities at once through the cascade. See
`opencti-front/src/private/components/nav/NavBar.tsx` (`accentColor`). The
workaround is one line, but it depends on a private token name: if the library
renames it, nothing breaks at build or at runtime — the accent silently falls
back to Filigran blue and the administrator's `theme_primary` is lost. That is
why `NavBar.test.tsx` carries a guard that reads the installed
`dist/index.css` and fails if no `aria-current=page` rule references the token
any more.

**Ask.** An `accent` (or `accentColor`) prop on `Navbar`, applied to the
selected-row border and tint, so a product with a themeable primary colour does
not have to reach for an internal token name.

**Removal test.** At a pin where that prop exists: delete the `accentColor`
block in `NavBar.tsx`, pass the same value to the prop, and confirm
`NavBar.test.tsx` still passes — it asserts the resolved accent, not the
mechanism.

---

## 2. `asChild` and the icon props are mutually exclusive, and both are required

**Needed.** Two things at once, both non-negotiable here:

- Navigation rows must be real anchors. Users Ctrl/Cmd-click and middle-click
  them; a button with an `onClick` is a functional regression.
- OpenCTI has a real user preference, `submenu_show_icons`, which hides the
  icons of submenu rows. `NavbarSubmenuItem` exposes exactly the matching
  `showIcon` prop, and `Navbar` exposes `submenuShowIcons` — a genuinely good
  fit, and one of the reasons this migration looked cheap.

**Today.** Real anchors are only reachable through `asChild`, and `asChild`
makes `icon` and `showIcon` no-ops (Radix's `Slot` cannot inject elements
inside an arbitrary child). So the product can have real links or the library's
icon handling, never both.

**Consequence.** `NavBar.tsx` composes the icon into its own `<Link>` and
re-implements the `submenu_show_icons` gate product-side, while still passing
`submenuShowIcons` to `Navbar` so the ambient context stays correct. The prop
the product was supposed to consume is inert on every row it renders.

**Ask.** Either give `NavbarItem` / `NavbarSubmenuItem` `href` / `to` props so a
link row stays library-owned (this is OpenAEV's entry 1, still open at this
pin), or make `asChild` compose rather than replace — for instance by slotting
onto a wrapper and keeping the icon/label spans library-rendered.

**Removal test.** At a pin where a link row keeps its icon handling: drop the
`submenuShowIcons &&` guard and the composed `<span>` in `renderSubItem`, pass
`icon` / `showIcon` to `NavbarSubmenuItem`, and confirm the
"hides submenu icons when the user preference is off" test still passes.

---

## 3. The collapse toggle's label is hardcoded English

**Needed.** OpenCTI ships nine locales. Every string the user can read is
translated, and the platform is used in non-English deployments.

**Today.** `Navbar` renders its own collapse toggle as the last row, with the
literal label `"Expand"` / `"Collapse"`. There is no prop to override it and no
localisation hook. The label is the row's accessible name, so it is what a
screen reader announces and what an end-to-end test has to match.

**Consequence.** Two user-visible English strings in an otherwise fully
localised interface, and an end-to-end page object anchored on English copy in
a suite that otherwise never is.

**Ask.** A `collapseLabel` / `expandLabel` pair on `Navbar` (or a single
`labels` object covering every string the component renders itself).

**Removal test.** At a pin where the props exist: pass
`t_i18n('Collapse') / t_i18n('Expand')` from `NavBar.tsx` and update
`leftBar.pageModel.ts` to match; nothing else changes.

---

## 4. A collapsed submenu parent navigates with a full page reload

**Needed.** In the previous rail, clicking a submenu parent while the rail was
collapsed navigated to that section — a client-side navigation, like every
other navigation in the application.

**Today.** `NavbarSubmenu` accepts `to`, and while collapsed it renders the
trigger as a bare `<a href={to}>`. That is the right element, but it is not the
router's `Link`, and `NavbarSubmenu` has no `asChild` escape hatch on its
trigger.

**Consequence.** This one navigation path reloads the whole single-page
application: the Relay store, the user context and every cached query are
rebuilt. The destination is correct, so it is not a defect a reviewer would
catch — only a user notices the pause. Recorded, and asserted as-is in
`NavBar.test.tsx` so the day it changes, the test says so.

**Ask.** Either an `asChild` (or `linkComponent`) escape hatch on the
`NavbarSubmenu` trigger, or a router-agnostic `onNavigate` callback the product
can wire to its own navigation.

**Removal test.** At a pin where the trigger can be a router `Link`: the
collapsed-parent test asserts `href` and the element being an anchor, both of
which a router `Link` also satisfies — so it passes unchanged, and the full
reload disappears.

---

## 5. Floating surfaces are portalled below the product's app bar

**Needed.** Submenu flyouts and tooltips from the collapsed rail must render
above the top bar.

**Today.** The library portals them to `document.body` with `z-50`. OpenCTI's
top bar sits at MUI's `theme.zIndex.drawer - 1`, i.e. 1199.

**Consequence.** One host rule in
`opencti-front/src/static/css/design-system-host.css` raises the portalled
wrapper above the app bar. It carries its own removal test in a comment.

**Ask.** Either a documented, overridable z-index token for portalled surfaces,
or a `container` prop so the product can portal them into its own stacking
context.
