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

---

## 6. Tokens derived from the brand colour cannot be overridden by a consumer

**Needed.** A product with an administrator-configurable accent must be able to
recolour the whole selected-row treatment, not part of it.

**Today.** `--color-filigran-brand-primary` can be overridden on a subtree, but
the tint the selected row is filled with comes from
`--color-filigran-brand-primary-transparency`, which the stylesheet declares on
`:root` as `color-mix(in srgb, var(--color-filigran-brand-primary) 10%,
transparent)`. Custom properties are substituted where they are *declared*, so
that derived token is frozen against the root brand colour: an override on the
`<nav>` moves the left border and leaves the fill Filigran blue.

**Consequence.** `NavBar.tsx` re-derives both `-transparency` and
`-transparency-50` inline, duplicating the library's own formula. If the ratio
changes in the library, the product silently disagrees with it.

**Ask.** Either declare the derived tokens with the same scope as the base one
(so a subtree override cascades into them), or expose the accent as a prop on
`Navbar` — which would remove this entry and entry 1 together.

**Removal test.** Delete the two derived-token lines from `navStyle`; the
selected row of a rail rendered under a custom accent must still be tinted with
that accent, asserted by the "overrides every custom property the installed
library resolves for the selected row" test in `NavBar.test.tsx`.

---

## 7. `asChild` rows must re-implement the row body, including the collapsed label

**Needed.** A row that is a real anchor (for Ctrl-click and "open in new tab")
should still render like a library row.

**Today.** `asChild` replaces the library's `<button>` with the consumer's
element, so besides the `icon`/`showIcon` props of entry 2, the internal body —
the icon wrapper, and the label span the library switches to `sr-only` while
the rail is collapsed — is not rendered either. A consumer that simply puts an
icon and a label inside its anchor gets labels overflowing a 48px rail; a
consumer that drops the label instead loses the accessible name the collapsed
rail is navigated by.

**Consequence.** `NavBar.tsx` reproduces the library's own body markup and its
`sr-only` switch, which couples the product to internal utility class names.

**Ask.** Either a `render`/`asChild` variant that keeps the library body and
only swaps the outer element, or an exported `NavbarItemBody` the consumer can
place inside its own anchor.

**Removal test.** At such a pin, replace `renderRowBody` with the library
element; the collapsed-rail tests asserting `role=link` with the exact
accessible name must still pass.

---

## 8. `Navbar` does not defend its own width in a flex host

**Needed.** The rail must occupy exactly the width it advertises, since the
product positions seven floating toolbars against that number.

**Today.** The `<nav>` carries `w-12` / `w-45` but no `shrink-0`. Dropped into
a flex row whose sibling is content-sized — which is what the MUI Drawer it
replaces lived in — it shrank to 22px, silently invalidating every offset
computed from the constants.

**Consequence.** One host rule (`.app-navbar { flex: 0 0 auto }`).

**Ask.** Add `shrink-0` to the `<nav>`'s own class list, as the library already
does on the rows inside it.

**Removal test.** Delete the host rule; the rail must still measure 48px
collapsed and 180px expanded at a 1500px viewport.

---

## 9. The same submenu entry answers to two different roles

**Needed.** End-to-end tests must anchor on what the component emits. A stable
anchor requires the same item to keep the same role whatever the rail state.

**Today.** A submenu child is a real anchor in both states, but its exposed
role is not the same: expanded, inside the accordion panel, it is a `link`;
collapsed, inside the portalled flyout, Radix's `DropdownMenu` overrides it to
`menuitem`. The parent row is a `button` when expanded and an `a` — carrying
`aria-expanded` all the same — when collapsed.

**Consequence.** `leftBar.pageModel.ts` carries two lookup strategies and can
only tell the states apart by the parent's role, not by `aria-expanded`.

**Ask.** Keep navigable submenu entries as `link` in the flyout too (Radix
allows opting out of the menu semantics), or document the role matrix so
consumers can anchor tests on it deliberately.

**Removal test.** At such a pin, use `getByRole('link', …)` in the collapsed
branch of `clickOnMenu`; `dashboard.spec.ts` must still pass.

---

## 10. Accordion state and hover flyout state share one controlled prop

**Needed.** A product needs to persist which submenus the user left open —
OpenCTI stores that in `localStorage` — so it controls `open`/`onOpenChange` on
`NavbarSubmenu`. The same props must not also drive transient hover behaviour.

**Today.** `NavbarSubmenu` resolves `isOpen = open ?? uncontrolledOpen` for both
of its two very different modes: expanded, `open` is the accordion's persisted
state; collapsed, the very same `open` is what shows or hides the hover flyout.
Leaving a row schedules `setOpen(false)` after `HOVER_CLOSE_DELAY_MS` (150 ms);
when the pointer has already reached the next row, that late callback and the
next row's `true` both resolve against the same state snapshot, so the last one
wins.

**Consequence.** Controlling the prop makes the collapsed rail unusable: the
first hovered submenu opens, every later one opens and closes immediately, and
hovering silently rewrites the persisted "open submenus" state. The product now
passes `open`/`onOpenChange` only when expanded, and lets the library own the
collapsed flyout — which means the persisted state is deliberately ignored in
the collapsed rail.

**Ask.** Separate the two states: keep `open`/`onOpenChange` for the accordion
and expose the flyout through its own prop (or keep the flyout uncontrolled by
construction), so a consumer can persist accordion state without breaking hover.

**Removal test.** Pass `open`/`onOpenChange` unconditionally in `NavBar.tsx`,
collapse the rail, then hover three submenu rows in a row: each flyout must open
and stay open while the pointer is on its row, and `localStorage.selectedMenu`
must be unchanged.

---

## 11. The rail is laid out in flow and sized by percentage

**Needed.** A left rail is expected to hold the full height of its shell and to
stay put while the content scrolls. Both products replace a fixed-position
drawer with the library `Navbar`.

**Today.** The library's `<nav>` participates in normal flow and sizes itself
with `h-full`, a percentage that only resolves against a parent with a definite
height. In an app shell whose height comes from its content — OpenCTI's — the
rail ends up shorter than the viewport and scrolls away with the page.

**Consequence.** Every host has to restore the two properties itself. Both
pilots landed on the same inline geometry (`position: sticky`, `top`, a definite
`height` computed from the viewport minus the shell's banners, and
`align-self: flex-start`). This is arguably the host's responsibility, so it is
filed as an observation rather than a defect — but two out of two consumers hit
it, which is the point.

**Ask.** Either document the layout contract the `<nav>` expects from its host
(definite-height parent), or let the component take the height it is given
(`min-h-0` + `self-stretch` on the `<nav>`, or an opt-in sticky mode).

**Removal test.** Delete the `navStyle` geometry block in `NavBar.tsx`; at a
1500×800 viewport the rail must still measure the full viewport height and keep
its position while an inner container scrolls.
