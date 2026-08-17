# Library feedback — OpenCTI → filigran-design-system

Gaps and friction found while consuming `@filigran/design-system` in this
product. Nothing here is fixed library-side: per the migration contract a
missing or awkward library capability is reported, never forked or worked
around inside the library. Each entry states what the product needed, what the
library offers today, what the product did instead, and the concrete ask.

Every workaround in the code is reduced to a single `FDS-WORKAROUND #N` marker
naming its removal condition and pointing here by entry number, so the two
cannot drift apart. The full rationale, the code shape and the removal test
live in the entry, not in the source — one place to read, one place to update.

Raised during: the navigation pilot (replacing `LeftBar.jsx` with `Navbar`),
library pin `56f7e59823cae7d815a451206e3cb4cb1d31022d`, then re-checked at
pin `486cec92c3abf006997ac269d34ff0fcc23f178f` (2026-08-06) and at pin
`5960966216533f620393a2174213c666f57af7dd` (2026-08-11, the token pass).

Closed so far: entries 5 and 12, both at the 2026-08-11 pin. Every other entry
was re-checked against that pin's source and its removal condition is still
unmet — the compensations stay, with the reason stated in each entry.

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
element, which recolours both utilities at once through the cascade. The colour
is resolved in the data component (`accentColor` in
`opencti-front/src/private/components/nav/NavBar.tsx`: `theme.palette.primary.main`,
or the warning colour when `draftContext` is set) and applied by the view
through `navStyle` — which additionally has to re-derive the tint token, see
entry 6. The workaround is one line, but it depends on a private token name: if
the library renames it, nothing breaks at build or at runtime — the accent
silently falls back to Filigran blue and the administrator's `theme_primary` is
lost. That is why `NavBar.test.tsx` carries a guard that reads the installed
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

**Consequence.** `NavBar.tsx` composes the icon into its own `<Link>` in
`renderSubItem` and re-implements the `submenu_show_icons` gate product-side
(`{submenuShowIcons && sub.icon}`), while still passing `submenuShowIcons` to
`Navbar` so the ambient context stays correct — and so this composition can be
deleted unchanged the day the library can inject an icon into a slotted child.
The prop the product was supposed to consume is inert on every row it renders.

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

## 5. Floating surfaces are portalled below the product's app bar — ✅ CLOSED at pin `5960966` (2026-08-11)

**Fixed by library PR #96** (`feat(overlay): let a host control overlay stacking
with --fds-z-overlay`), which routes all six floating surfaces — the Dialog panel
and its scrim, `TooltipContent`, `SelectContent`, `Menu`'s shared panel and the
`NavbarSubmenu` flyout — through `var(--fds-z-overlay, 50)`. Radix then
propagates the *resolved* value onto the wrapper's inline style on its own,
which is what puts it back within a host's reach.

**Compensation retired.** The `body > [data-radix-popper-content-wrapper] {
z-index: 1300 !important }` rule is gone from
`opencti-front/src/static/css/design-system-host.css`, replaced by a plain
`:root { --fds-z-overlay: 1300 }` — same level, no `!important`, no dependence
on a Radix-internal attribute selector. The value is unchanged, so this is
iso-functional with what it replaces.

The history below is kept as the record of why the rule existed.

---


**Needed.** Submenu flyouts and tooltips from the collapsed rail must render
above the top bar.

**Today.** The library portals them to `document.body` with `z-50`, and Radix
copies that value *inline* onto the `[data-radix-popper-content-wrapper]` it
appends to `<body>`. OpenCTI's top bar sits at MUI's `theme.zIndex.drawer - 1`,
i.e. 1199, so every library menu, flyout and tooltip paints underneath it.

**Consequence.** One host rule in
`opencti-front/src/static/css/design-system-host.css` raises the portalled
wrapper above the app bar:

```css
body > [data-radix-popper-content-wrapper] { z-index: 1300 !important; }
```

1300 is MUI's own `zIndex.modal` — the level the MUI popovers being replaced
already used, so this is iso-functional with the rail it succeeds rather than a
new stacking choice. `!important` is not stylistic: the value Radix writes is
inline, and an inline declaration cannot be overridden by a normal rule.

**Ask.** Either a documented, overridable z-index token for portalled surfaces
(the concrete ask is a `--fds-z-overlay` custom property, so a host can set it
once on `:root`), or a `container` prop so the product can portal them into its
own stacking context.

**Removal test.** At a pin exposing a stacking hook: delete the host rule, set
the variable on `:root`, then open a collapsed-rail submenu flyout over the top
bar in both themes and confirm the wrapper computes above 1199:

```js
[...document.querySelectorAll('body > [data-radix-popper-content-wrapper]')]
  .map((w) => getComputedStyle(w).zIndex) // must be > 1199
```

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
`-transparency-50` inline in `navStyle`, duplicating the library's own formula:

```ts
navStyle['--color-filigran-brand-primary'] = accentColor;
navStyle['--color-filigran-brand-primary-transparency'] = `color-mix(in srgb, ${accentColor} 10%, transparent)`;
navStyle['--color-filigran-brand-primary-transparency-50'] = `color-mix(in srgb, ${accentColor} 50%, transparent)`;
```

The observed symptom without the last two lines: under a custom accent the left
border followed the custom colour while the row tint stayed Filigran blue — a
half-applied accent, which reads as a rendering bug rather than a missing
feature. If the ratio changes in the library, the product silently disagrees
with it; that drift is what the token-name guard in `NavBar.test.tsx` watches.

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
the rail is collapsed, showing its tooltip instead — is not rendered either. A
consumer that simply puts an icon and a label inside its anchor gets labels
overflowing a 48px rail; a consumer that drops the label instead loses the
accessible name the collapsed rail is navigated by.

**Consequence.** `NavBar.tsx` reproduces the library's own body markup and its
`sr-only` switch verbatim, in `renderRowBody`:

```tsx
<span className="inline-flex shrink-0" aria-hidden="true">{icon}</span>
<span className={collapsed ? 'sr-only' : 'flex-1 truncate text-left'}>{label}</span>
```

Hiding the label rather than dropping it is the whole point: it is what keeps
the collapsed rail navigable by screen reader and keeps the e2e page object's
name lookups working. This couples the product to internal utility class names.

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

**Today.** The `<nav>` carries `w-12` / `w-45` but no `shrink-0`. The private
layout is a flex row whose main region is content-sized, so the row overflows
and the browser shrinks every shrinkable item. The MUI Drawer this rail replaces
was immune because MUI ships `flex: 0 0 auto` on the Drawer root — which is why
the defect appears only on migration. Dropped into that same flex row, the
library `<nav>` shrank from 48px to 22px, silently invalidating every offset
computed from the constants.

**Consequence.** One host rule (`.app-navbar { flex: 0 0 auto }`) in
`opencti-front/src/static/css/design-system-host.css`. Silent is the operative
word: nothing throws, and the only visible symptom is that the seven floating
toolbars aligned on `SMALL_BAR_WIDTH` / `OPEN_BAR_WIDTH` sit at the wrong
offset.

**Ask.** Add `shrink-0` to the `<nav>`'s own class list, as the library already
does on the rows inside it.

**Removal test.** At a pin where the library adds `shrink-0` to the `<nav>`,
delete the host rule, then measure the running rail at a 1500px viewport:

```js
document.querySelector('nav.app-navbar').getBoundingClientRect().width
```

must be 48 collapsed and 180 expanded.

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
first hovered submenu opens, every later one opens and closes immediately —
because the late `false` and the next row's `true` resolve against the same
snapshot and the last one wins, closing the flyout that just opened. It also
wrote hover into the persisted menu state, which merely *pointing at* a row
never did before: simply sweeping the pointer down a collapsed rail rewrote
what the user would find open on next login. The product now binds the pair
only while expanded, and lets the library own the collapsed flyout:

```tsx
open={collapsed ? undefined : openSubmenus.includes(item.id)}
onOpenChange={collapsed ? undefined : (open) => onSubmenuOpenChange(item.id, open)}
```

The trade-off is deliberate and worth stating: the persisted state is ignored
in the collapsed rail, which is acceptable because a flyout is transient by
nature, whereas an unusable rail is not.

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

**Consequence.** Every host has to restore the two properties itself. Measured
in OpenCTI before the fix: the rail rendered 776px tall in an 800px viewport and
scrolled away with the page, where the MUI Drawer it replaces was
fixed-positioned and full height — so this is a functional regression, not a
styling preference. Both pilots landed on the same inline geometry, applied to
the `<nav>` via `style` in
`opencti-front/src/private/components/nav/NavBar.tsx` (`navStyle`):

```ts
position: 'sticky',
top: topOffset,                                        // banners at the top
alignSelf: 'flex-start',
height: `calc(100dvh - ${topOffset} - ${bottomOffset})`,
```

The OpenAEV pilot solved it identically, in
`openaev-front/src/components/common/menu/navbar/AppNavbar.tsx` — the reference
implementation to read before touching this. Note the division of labour:
`flex-shrink` is *not* part of this block, it is supplied by the host stylesheet
and tracked separately as entry 8, so the two can be retired independently.
This is arguably the host's responsibility, so it is filed as an observation
rather than a defect — but two out of two consumers hit it, which is the point.

**Ask.** Either document the layout contract the `<nav>` expects from its host
(definite-height parent), or let the component take the height it is given
(`min-h-0` + `self-stretch` on the `<nav>`, or an opt-in sticky mode).

**Removal test.** Delete the `navStyle` geometry block in `NavBar.tsx`; at a
1500×800 viewport the rail must still measure the full viewport height and keep
its position while an inner container scrolls.

---

## 12. The pointer-cursor fix stopped at `NavbarItem` and left `ProductSwitcher` behind — ✅ CLOSED at pin `5960966` (2026-08-11)

**Fixed by library PR #94** (`fix(cursor): declare the pointer cursor on the
shared interactive layers`), which took the generalisation this entry asked for
rather than repeating the per-component fix: the cursor now lives on
`buttonVariants`, `iconButtonVariants`, `TabsTrigger`, `SelectTrigger` and
`Switch`'s control root. `iconButtonVariants` alone settles `ProductSwitcher`'s
24×24 trigger, and with it Dialog's close button, SearchField's action slot,
Input's end icon, Menu's triggers and Chip's delete button.

**Nothing to retire.** This pilot deliberately filed the gap instead of writing
a host rule, so closing it removes no product code — which is the whole point of
having filed it that way.

The history below is kept as the record of what was measured when it was open.

---


**Found at pin `486cec92c3abf006997ac269d34ff0fcc23f178f`,** re-checking the rail
after library PR #84 (`fix(navbar-item): give button-rendered rail rows the
pointer cursor`) landed.

**Needed.** Every interactive row of the rail should show the hand cursor. The
MUI navigation this pilot replaces did, on all of them, and the loss is visible
on first use.

**Today.** PR #84 declares `cursor-pointer` once on `NavbarItem`'s shared row
class, which fixes both of that component's render paths. Measured in the
running platform, that took OpenCTI's rail from 0/14 to 13/14 button-rendered
rows carrying `cursor: pointer` — collapsed, 1/1. The remaining row is the
`ProductSwitcher` trigger, which is a sibling component and therefore not a
`NavbarItem`: it renders its own `<button>`, declares no cursor, and still
resolves to `cursor: default`.

**Consequence.** The rail is inconsistent again, in exactly the way PR #84 set
out to end — one arrow cursor among fourteen hands, at the top of the rail where
it is most visible. No product compensation was added: this pilot files it
rather than papering over it, because a host-side rule would hide the gap from
every other consumer.

**Ask.** Declare the same `cursor-pointer` on `ProductSwitcher`'s trigger. More
generally, PR #84's own reasoning ("a browser gives `<a href>` a hand cursor for
free and gives `<button>` nothing") applies to every button the library renders,
not only to rail rows — the fix is worth generalising rather than repeating.

**Removal test.** At a pin where it is fixed: open the expanded rail in the
running platform and read the computed `cursor` of every `<a>` and `<button>`
inside `nav.app-navbar`; all of them must be `pointer`, with no exception for
the switcher.

---

Entries 13–20 were raised by the Header pilot (admin top bar), at pin
`5960966216533f620393a2174213c666f57af7dd`. Several restate what the OpenAEV
Header pilot already filed; where they do, its entry number is given so the
library sees two consumers, not one.

---

## 13. `IconButton` renders a hard `<button>` and accepts no `asChild`

**Needed.** Two bar controls (Triggers, Notifications) are genuine routes. As
buttons with an `onClick` they would lose middle-click, ⌘/Ctrl-click, "copy link
address" and the status-bar preview — a behavioural loss.

**Today.** `IconButton` hard-renders `<button>` with no `asChild`, while
`Button` has one.

**Consequence.** `TopBarIconLink.tsx` applies `iconButtonVariants` to a router
`Link`, re-implementing the component's DOM contract (the `aria-hidden` glyph
wrapper) by hand. Same technique as OpenAEV's entry 21.

**Ask.** Give `IconButton` the `asChild` `Button` already has.

**Removal test.** Delete `TopBarIconLink.tsx`, wrap `<Link>` in
`<IconButton asChild>`; the icon-link tests stay green.

---

## 14. `Header` ships no positioning, so every product re-invents it

**Needed.** A top bar fixed to the viewport, offset by the navigation rail and
by up to three stacked banners.

**Today.** `Header` is laid out in flow and never sticky, by design.

**Consequence.** The product supplies `position: fixed`, `top`, `left`, `right`
and `z-index` inline, and `fullWidth={false}` with them. Same as OpenAEV's
entry 20 — two consumers out of two.

**Ask.** Either document the positioning contract, or an opt-in fixed mode.

**Removal test.** Delete the inline block; the bar must stay fixed, flush with
the rail, under the banners.

---

## 15. A themeable surface has no supported hook for a product-driven colour

**Needed.** OpenCTI administrators set `theme_background` per theme; it paints
the top bar's gradient. Adopting `Header` as-is would drop that.

**Today.** The glass layer reads `--gradient-default`, a token assembled at
`:root`. Overriding its stops at `:root` would repaint every other library
surface — the Navbar included — while still failing to repaint a gradient
already assembled there.

**Consequence.** The product re-declares the whole assembled gradient on the bar
element. Same ask as OpenAEV's entry 17.

**Ask.** A documented per-surface background hook.

**Removal test.** Replace the re-declaration with the supported hook; a custom
`theme_background` must still paint the bar and nothing else.

---

## 16. Layered utilities lose to the host's unlayered CSS

**Needed.** The selected icon link must carry the same background `IconButton`
paints for `active`.

**Today.** The library's utilities are layered; a class added on the same
element by a product that composes by hand loses to unlayered host CSS.

**Consequence.** `TopBarIconLink` sets the background inline, from the library's
own token rather than a literal. Same failure mode as OpenAEV's entry 24.

**Ask.** Document the layer contract consumers must respect.

**Removal test.** Move the background back to a class; the active link must stay
tinted.

---

## 17. `HeaderGroup`'s `grow` caps below this bar's ceiling

**Needed.** A search window of 200–500px.

**Today.** `grow` caps at 400px; `grow="unbounded"` removes the cap entirely.

**Consequence.** The product uses `grow="unbounded"` and declares the window on
the group it owns. Same as OpenAEV's entry 18.

**Ask.** Let `grow` take the cap as a value.

**Removal test.** Replace the inline window with the prop; measured width must
stay 200–500px.

---

## 18. No general-purpose separator

**Needed.** A rule between the AI actions and the platform actions.

**Today.** `NavbarSeparator`, `MenuSeparator` and `SelectSeparator` are each
bound to their own component.

**Consequence.** A `div role="separator"` painted from the library's border
token. Same as OpenAEV's entry 22.

**Ask.** A standalone `Separator`.

**Removal test.** Replace the div with the component; the rule keeps its
geometry and colour.

---

## 19. No `Badge` — ✅ CLOSED at pin `8798cbb` (2026-08-13)

**Shipped by library PR #114.** The bar's unread marker is now the library
`Badge`: `content` carries the total, `dot` renders the reduced form ("there is
something, do not show how much"), and `invisible` unmounts it when nothing is
unread — the same three behaviours the MUI badge provided.

Measured after: zero `MuiBadge-` elements remain in the bar, and with nothing
unread the badge is not mounted at all, so no empty node is left behind.
`TopBar.libraryOnly.test.ts` now names `MuiBadge-` among the classes the bar
must not carry, so a regression fails the suite rather than a review.

The history below is kept as the record of what was missing.

---

### Original report — No `Badge`

**Needed.** The unread dot on the notifications control.

**Today.** The library ships no badge.

**Consequence.** MUI's `Badge` wraps the glyph inside the library-styled link.
Named in OpenAEV's entry 22 as a gap worth sizing.

**Ask.** A `Badge`, dot and count variants. Understood to be in progress.

**Removal test.** Swap MUI's `Badge` for the library's; the dot must keep its
position and its `invisible` behaviour.

---

## 20. `SearchField` has no busy state and no themeable leading icon

**Needed.** While a natural-language query runs, the field must show it is
working; and when NLQ mode is on, the leading magnifier is tinted with the AI
colour so the mode is visible at the field itself.

**Today.** `SearchField` renders its own magnifier and clear cross and exposes
neither a busy state nor a hook for the leading icon's colour. `searchOption` is
a trailing slot for actions, not a status area.

**Consequence.** Adopting `SearchField` for the top bar dropped three
affordances the product had: an animated gradient border while NLQ is active,
the AI-tinted magnifier, and an inline loader inside the field. The loader now
sits beside the field; the other two are gone. The NLQ mode remains readable
from the toggle's own selected state.

**Ask.** A `busy`/`loading` state, and a documented way to colour the leading
icon.

**Removal test.** Pass the busy state and the icon colour; the loader returns
inside the field and the magnifier tints with NLQ on.

---

## 21. The bar's EE marker is decorative — a recorded decision, not a gap

**Decision (Sandy, 2026-08-12).** In the top bar the "EE" marker is information,
not a control: the surrounding "Ask Ariane" button owns the click and opens the
dialog, and the chip only signals that the feature belongs to the enterprise
pack. It is therefore rendered without `onClick`.

**Why it is also the only valid shape here.** `Chip` renders a `<button>` as
soon as `onClick` is present, and nesting that inside the Ask Ariane button
would be invalid. The decision and the constraint agree, so nothing is being
worked around.

**Elsewhere.** The 26 other `EEChip` call sites keep the legacy marker and its
click, which opens the enterprise-edition dialog. Converting them is its own
change.

**Settled at pin `7e7b417`.** The `tone` axis is gone; the marker is
`severity="ee"` and was re-checkpointed on the three themes, at rest and on
hover. The 8px between the label and the chip is now carried entirely by the
chip's own margin: the library button lays its label out as a bare text node,
so no flex gap falls between the two — measured, not assumed.

---

## 22. `Menu` shows its focus ring on hover — ✅ CLOSED at pin `990810f` (2026-08-12)

**Fixed by library PR #110** (`fix(menu): keep the keyboard focus ring off rows
the pointer highlights`). Measured after the bump: hovering an item still gives
it DOM focus and `:focus-visible` — that is Radix's own semantics — but the
ring now resolves fully transparent (`rgba(0, 0, 0, 0) 0px 0px 0px 0px`), so
only the hover background paints. The keyboard affordance is unaffected.

The history below is kept as the record of what was measured when it was open.

---

### Original report — `Menu` shows its focus ring on hover

**Found at pin `5960966`.** Reported from the running product.

**What happens.** Moving the pointer over a `MenuItem` gives it real DOM focus:
measured `document.activeElement === item`, `:focus-visible` matches, and
`data-highlighted` is set. The library's own `focus-visible:ring-2`,
`focus-visible:ring-offset-2` and `ring-focus` classes therefore fire, painting
the brand-blue ring — the keyboard affordance — under the mouse.

**Scope.** Not specific to link items: reproduced on a plain `<div>` item
(Feedback) as well as on `asChild` anchors. The product passes only `asChild`
and `onSelect`, so nothing product-side is involved.

**Ask.** Separate the hover treatment from the focus ring, so the ring stays a
keyboard affordance.

**Removal test.** Hover a `MenuItem` with the mouse: no focus ring; reach the
same item with the keyboard: ring present.

---

## 23. ~~`ProductSwitcher` truncates product names~~ — WITHDRAWN, it was ours

**Filed in error, 2026-08-12.** This entry blamed the library's panel geometry.
It was the product: `NavBar.tsx` passed `width={126}` — the trigger slot's width
— to the two *option* logos, whose slot is 100px. The images overflowed their
slot by 26px and were clipped, which read as truncated wording.

**Fixed product-side**, on the OpenAEV pilot's own model
(`LeftBarHeader.tsx`): `style={{ width: '100%', height: 'auto', objectFit:
'contain' }}`. Measured in the running product — before: both logos 126px in a
100px slot, 26px overflow, clipped. After: both 100px in a 100px slot, no
overflow, aspect preserved, "OpenAEV" and "XTM Hub" fully legible.

The trigger's own logo keeps `width={126}`: its slot is that wide, and it is
correct.

**Lesson for the next entry.** The measurement that misled me was reading the
label span's width and the `shrink-0` logo slot, and concluding the library
sized them wrongly. It did not: the product oversized the image inside them. A
gap should be filed against the library only after checking what the product
passes in.

---

## 24. No segmented control, so the bar's mode toggles stay MUI

**Last measured at pin `35a4768`:** `ToggleButtonGroup`, `ToggleButton` and the
`ButtonBase` they render are the only non-glyph MUI left in the bar — and they
now block a second conversion as well.

**It also blocks the NLQ dropdown.** That menu has a library equivalent
(`Menu`/`MenuItem`/`MenuSeparator`), but its trigger does not: the caret is a
`<span>` *inside* a `ToggleButton`, and the menu anchors to it. A Radix
`MenuTrigger asChild` would have to clone onto a non-focusable span, and
without `asChild` it renders a `<button>` inside the `ToggleButton`'s own
button. Both are wrong, so the menu stays MUI until the group does not.

**Measured values, so the component can be specified** (dark theme, bar
running):

| | |
|---|---|
| Group | 84 × 36 px, `role="group"`, radius 4px, transparent background |
| Segments | 2 × 36 × 36 px, padding 0, radius 4px, 18px glyph |
| Gap between segments | 6px |
| Selected | background `rgba(66,202,255,0.25)`, glyph `rgb(255,255,255)` |
| Unselected | transparent background, glyph `rgb(66,202,255)` |
| Semantics | `aria-pressed` true/false, **one tab stop per segment** — no roving focus |
| Third segment | appears for natural-language search when XTM One is configured |

The tab-stop behaviour is worth a decision rather than a copy: the MUI group
gives each segment its own tab stop, where a segmented control usually carries
one stop for the group and arrow keys between segments.

**Needed.** The bar exposes two mutually exclusive search modes — advanced
search and bulk search — as a segmented pair, and a third segment appears for
natural-language search when XTM One is configured. Selection is exclusive,
each segment is a toggle rather than an action, and the group is one tab stop
with arrow-key movement between segments.

**Today.** The library ships `Button`, `IconButton` and `Chip`; none of them
carries selected state as a group. The pilot therefore leaves
`ToggleButtonGroup` + `ToggleButton` on MUI. They are the last rendered MUI
components in the bar, and the reason `TopBar.libraryOnly.test.ts` asserts a
named survivor list rather than zero MUI.

**Asked.** A grouped, single-select control — the segments themselves can be
the existing `IconButton`, what is missing is the group that owns exclusivity,
roving focus and the selected style.

### The `Popover` that comes with it

**Exempted by Sandy, 2026-08-13, with this entry.** No product line imports a
`Popover`: it reaches the page because MUI draws the exempted menu with one
(`MenuRoot = styled(Popover)` in `@mui/material`). The library exports none
either — checked on the installed build at pin `35a4768`, not inferred from a
changelog: `Popover` is absent from `dist/index.d.ts`, while the Radix
dependency it would be built on is already there. Sandy still has to design it.

**Retired by** the same event as the rest of this entry: a library segmented
control removes the menu's MUI trigger, and the library's own floating layer
replaces the popover under it. `TopBar.libraryOnly.test.ts` names `Popover` in
`EXEMPTED` so that importing one directly stays a declared, dated exemption
rather than a new arrival.

**Not exempted, and now closed:** `Stack` and `Box` were still inside the NLQ
toggle — MUI layout, not the control. Replaced by plain elements at the same
geometry (4px caret margin and padding, unchanged 1px divider). The guard reads
`SearchInput.jsx` by symbol from now on, so either one coming back fails
instead of passing under an exemption written for named components.

---

## 25. The gradient-text recipe breaks on any nested component — ✅ CLOSED at pin `7e7b417`

**Where it bit.** `variant="ia"` paints its label with
`background-clip: text` + `-webkit-text-fill-color: transparent`. That fill
**inherits**, and it beats `color` on the descendant. Any component nested in
such a button — for this bar, the EE chip inside "Ask Ariane" — paints its
glyphs invisible: the chip rendered as a coloured pill with no "EE" in it, in
both themes.

The library documents the trap in its own source ("breaks if the child has
nested elements"), which makes it a known sharp edge rather than a surprise —
but a consumer only meets it after shipping the bug.

**Fixed product-side** in `createTextGradientSx`: element children get
`-webkit-text-fill-color: currentColor` back, bare text nodes keep the
gradient. Measured on the bar's chip (8px from the label, own fill and
background restored, at rest and on hover, dark and light) and on the
product's text-only gradient buttons, which have no element children and are
therefore unchanged.

**Shipped by library PR #116** — ✅ CLOSED at pin `7e7b417`. The built CSS now
carries `.text-gradient-*>*{-webkit-text-fill-color:currentColor}`.

**One difference worth naming, because it bit us.** The library hides the label
with the fill alone; OpenCTI's own `createTextGradientSx` also set
`color: transparent`. With both, the reset resolves `currentColor` back to
transparent and a nested child stays invisible anyway — the reset only works
because the colour underneath it is real. The product recipe was aligned on the
library's, and a test fails if `color: transparent` returns.

---

## 26. A library `Tooltip` throws without a `TooltipProvider`, and nothing says so at the type level

**Where it bit.** The bar had a `TooltipProvider` and no other screen did. Moving
the import control onto the library `Tooltip` made it throw — *"`Tooltip` must be
used within `TooltipProvider`"* — on the three screens outside the bar that
render the same control. TypeScript compiled it, ESLint passed it, and the bar
itself looked fine: only a rendered-DOM test caught it.

**Fixed product-side** by providing once at the private app's root, which is the
Radix-recommended placement, and dropping the bar's own.

**Asked.** Nothing about the API — this is Radix's contract and the error message
is good. Worth a line in the `Tooltip` documentation page saying where a product
is expected to mount the provider, so the first consumer does not discover it
through a crash on a screen they were not looking at.

---

## 27. `Badge`'s default tone changed under a consumer, and nothing announced it

**What happened.** At pin `35a4768` (library PR #119) the default `tone` moved
from `brand` to `error`. The bar's unread marker passes no `tone`, so it went
from the brand blue to red without a line of product code changing.

That is a legitimate library decision — an unread count arguably *is* an alert —
and the product is taking the new default rather than pinning the old look. But
a default that repaints a shipped consumer is a breaking visual change, and this
one arrived inside a feature commit titled for the Spinner's new tier.

**Measured, so the choice can be made on values rather than memory:**

| Theme | Default (`error`) | `tone="brand"` |
|---|---|---|
| Dark | `rgb(136,17,6)` counter, `rgb(241,67,55)` dot | `rgb(66,202,255)` |
| Light | `rgb(245,114,102)` counter, `rgb(184,24,10)` dot | `rgb(0,21,168)` |
| Custom | `rgb(136,17,6)` counter, `rgb(241,67,55)` dot | `rgb(66,202,255)` |

**Asked.** Flag a default-value change in the release note the way a removed
prop would be. A consumer cannot diff what it never wrote.

---

## 28. `Badge` describes the element it is given, so it must be given the control

**Not a library defect — a consumer trap the API cannot see.** `Badge` clones
`aria-describedby` onto its single child element. The bar handed it the glyph,
and `TopBarIconLink` renders the glyph inside `aria-hidden="true"`, exactly as
`IconButton` does. The reference therefore landed on a node outside the
accessibility tree.

**Measured through CDP** (`Accessibility.getPartialAXTree` on the anchor), the
three themes, before: role `link`, NAME `"Notifications"` from
`attribute[aria-label]`, **DESCRIPTION `""`** — the count was announced by
nobody, while a DOM sweep found the text and read as if it worked. That is the
whole point of measuring the computed tree instead of the markup.

**After**, the badge wraps the anchor: NAME `"Notifications"`, **DESCRIPTION
`"5 unread"`**, `aria-describedby` on the `<a>` itself, in dark, light and a
custom theme.

**Ask.** A dev-only warning when the element `Badge` is about to describe is
`aria-hidden`, or sits inside something that is — the same shape as the
existing warning for a non-element child. It is cheap and it catches the one
mistake the type system cannot.

---

## 29. A component that names its props swallows what `asChild` clones onto it

**Ours, found by the same pass, and worth writing down for the next pilot.**
`TopBarIconLink` destructured the five props it knew about. `TooltipTrigger
asChild` clones its handlers, its `data-state` and its ref onto that component,
and every one of them was dropped: measured, the Triggers and Notifications
tooltips **never opened**, on pointer or on keyboard, while the tooltip on the
library `IconButton` next to them did. Nothing was red; the markup looked
right.

Fixed by forwarding the ref and spreading the rest onto the anchor — and
`className` and `style` are merged rather than spread, because a cloning parent
passes `className: undefined` and that replaced the library variant outright:
the control measured **24×28 instead of 36×36**, with no size class left on it.
Both are guarded by tests now.

**Lesson for the playbook.** A hand-rolled stand-in for a library component
(entry 13's `IconButton asChild` gap is what forces one here) must forward ref
and rest props, or it is not a drop-in — and the failure is silent in both
directions.

---

Raised during: the **Paper pilot, phase 0** — bump from pin `35a4768` to
`a22b188b28bc151f930d19d4f8ed7114df581e6e` (tête d'`origin/main`, carrying
#121, #123/#124 and #125). Everything below is measured on the DOM rendered by
the installed build, in this product's real MUI theme, with the app's complete
stylesheet stack loaded. Entries 30-33 are Paper gaps; 34-35 are method
findings the next bump will hit again.

**Closed by this bump, re-measured rather than assumed:** the `padding` prop
exists on the 0/8/16/24/32 scale and all five classes ship in `dist/index.css`;
`title`/`action` are real props rendering a header row above the surface;
the host-theme contract works in both directions (re-declaring the per-layer
base repaints, re-declaring the alias does nothing); the border is its own
`--border-elevation-subtle-soft` token at 15 % dilution.

## 30. An off-scale `padding` still renders 0px — and OpenCTI's two commonest values are off-scale

Same defect OpenAEV raised as its #32, unchanged at this pin, but the blast
radius here is different enough to re-state.

**Measured on the installed build:** `<Paper padding={15}>` and
`<Paper padding={20}>` both render **no padding class at all** — computed
padding **0px**. Not the default 24, not the nearest step, no warning.

**Why it is worse in this product.** OpenAEV's call sites were at 0 and 16, so
the trap was reachable only by mistake. OpenCTI's 28 container surfaces measure:

| padding | sites |
|---|---|
| 0 | 15 |
| **15** | **4** |
| 16 | 3 |
| **20** | **2** |
| asymmetric | 3 |

**15 and 20 are the values an agent converting these files will reach for
first**, because they are what the source says. TypeScript rejects them in a
`.tsx`, but `StixDomainObjectAuthorKnowledge.jsx` is `.jsx` and this product's
tsconfig sets `allowJs` without `checkJs` — no prop checking at all there. A
dynamic value escapes the types even in `.tsx`.

**Ask.** Unchanged from OpenAEV #32: make the runtime say something, per
AGENTS.md "Prop contract violations — dev-only warning, never throw". The
`warnOnUnsupportedProps` helper already shipped in this pin covers *unknown*
props; it does not cover a *known* prop with an off-scale value. That is the
one line missing.

---

## 31. The `padding` scale cannot express 15px, 20px, or any asymmetric padding

**Needed.** An iso-density migration: each converted surface keeps exactly the
padding it renders today.

**Today.** The scale is 0/8/16/24/32 and the prop is **uniform**. Measured
against OpenCTI's real values, **9 of 28 sites (32 %) are inexpressible**:

| value | sites | nearest expressible | cost |
|---|---|---|---|
| `15px` | 4 | 16 | **+1px on all four sides** |
| `20px` | 2 | 16 or 24 | **±4px, equidistant** — no "nearest" exists |
| `8px 15px 0 15px` | 2 | — | asymmetric, **inexpressible** |
| `20px 20px 0 20px` | 1 | — | asymmetric, **inexpressible** |

**The escape hatch does not exist here.** OpenCTI does not compile Tailwind; it
consumes the pre-built sheet, so `className="p-[15px]"` resolves to nothing.
And re-adding a hardcoded padding class on a library Paper is exactly what this
migration's conformity guard is meant to redden.

**Ask.** Two separable questions, and the first is the cheap one:

1. **Is the scale the whole answer?** 15 and 20 are not design decisions in
   OpenCTI, they are pre-token legacy — a design arbitration that says "15
   becomes 16" would close 4 sites at a stroke. That is Sandy's call, not the
   library's, but the library should say whether it *wants* to grow steps or
   wants products to converge onto the scale.
2. **Asymmetric padding.** Three sites use a bottom-less padding
   (`… 0 …`) so that a child's own trailing margin does not double up. If the
   answer is "never", those three leave the Paper waves permanently and should
   be recorded as such, the way `DetailHero` was.

---

## 32. `Paper`'s border cannot be turned off, and it has no shadow — 7 sites need both

**Needed.** OpenCTI's container surfaces are **not** uniform. Measured:

| | sites | border | shadow |
|---|---|---|---|
| `variant="outlined"` | **21 / 28** | `1px solid rgba(255,255,255,.12)` | `none` |
| no `variant` | **7 / 28** | **`0px none`** | **MUI elevation shadow** (`rgba(0,0,0,.2) 0 2px 1px -1px, …`) |

The library `Paper` draws a border at every elevation, always, and measures
`box-shadow: none` at all four. So for those 7 sites a swap **adds** a border
that is not there and **removes** a shadow that is — two losses at once, and
neither is expressible.

For the other 21 this entry does not apply: the border is present on both
sides and only the tone differs (product 1,32:1 against its own surface; library
1,09:1 dark, 1,15:1 light). That is the tone #125 deliberately chose and it is
not raised as a defect.

**Ask.** Not necessarily a `border={false}` prop. The question to settle is
whether a surface that delimits itself by **shadow** rather than by **border**
is a Paper at all in this design system, or a different component — the same
shape of question `DetailHero` forced. Either answer unblocks these 7; no
answer leaves them on MUI while everything around them moves.

---

## 33. `title` / `action` exist now, and are still not adoptable here

**Not a blocker** — the wave's arbitration already says the product keeps its
own header when the library's is not ISO. Recorded with OpenCTI's numbers so the
decision is not re-litigated per product.

Two sites have a title above the surface (`ScaleConfiguration.tsx:209`,
`StixDomainObjectAuthorKnowledge.jsx:273`), both
`<Typography variant="h4" gutterBottom>`. Measured against the library's row:

| | product | library |
|---|---|---|
| height | **15,0 px** | **24,0 px** |
| weight | 500 | 400 |
| line-height | 14,82 px | 18 px |
| letter-spacing | `normal` | 0,09 px |
| colour | primary `rgb(242,242,243)` | secondary `rgb(175,176,182)` |
| gap to surface | 4,2 px | 8,0 px |

**+12,8 px of vertical per panel**, plus a weight and colour change. Not ISO.

**The second half matters more.** OpenCTI's dominant "titled panel" shape is not
a title above the surface at all — it is a **banner inside** it: eight sites
(`sso_definitions/*`) render `<Box sx={{ px: 2, py: 1.5, backgroundColor:
'action.hover' }}>` as the Paper's first child, clipped to the radius by
`overflow: hidden`. `title` renders **above** the surface, outside the border,
with no background. It cannot express this shape at any typography.

**Ask.** Nothing urgent. But if a titled-surface variant is ever specified,
the inset-banner shape is the one this product actually uses, 8 times to 2.

---

## 34. The token rename left three dead references in this product — and all three were silent

OpenAEV raised this as its #33 with three dead references, one of them loud (a
TypeScript error). **In OpenCTI all three are silent**: `tsc --noEmit` passes
with zero errors, eslint passes, the build passes.

| reference | file | shape | measured consequence |
|---|---|---|---|
| `var(--color-filigran-brand-primary-transparency)` **read** | `TopBarIconLink.tsx:8` | dangling `var()` in a string | the selected top-bar link's background has no value. `TopBar` and `NavBar` are **siblings** (`private/Index.tsx:122-123`), so no product ancestor declared it. |
| `--color-filigran-brand-primary-transparency` **declared** | `NavBar.tsx:101` | a product-set custom property nothing reads any more | the library's Navbar renders `bg-filigran-brand-primary-transparency-10`, which reads the **new** name. Measured: the selected row painted `srgb(0.259,0.792,1)` — **Filigran default blue** — instead of the customer accent `#ff8a3d`. |
| the same literal, **asserted** | `TopBarIconLink.test.tsx:29` | the test compares the string, not the resolved colour | it stayed **green** on a dead reference. |

The second one is the new shape worth naming: a rename breaks not only what a
product **reads** but also what it **writes**. A host that re-declares a token
to theme a library component is, by construction, coupled to the token's name —
and there is no signal at all when the library stops reading it.

**Ask.** Unchanged and still small: a machine-readable rename map in the
release (old name → new name) so a consumer can grep for the old names rather
than having to notice their absence. The write direction makes it more valuable,
not less — a consumer can only audit its own declarations against a list of what
the library actually reads.

**Method note for the next bump, OpenCTI included.** Regenerating the bridge is
necessary and not sufficient. Grep the whole product source — not the
`wiredFiles` — for `var(--token)` in string literals **and** for library utility
classes written as literals, then cross-check every hit against the tokens and
classes actually present in the **installed** `dist/index.css`. Add a third
sweep the OpenAEV entry did not have: **every custom property the product sets**
(inline `style`, CSS files) whose name belongs to the library's namespace.

---

## 35. A product `:focus { outline: 0 }` is here too

Exactly OpenAEV's #34, same rule, same file role: `src/static/css/index.css:26`
carries `:focus { outline: 0 }`, applying to every focusable element in the
application, and it wins over the library sheet.

Nothing is broken today — #123 replaced the navbar's focus ring with an **inset
border**, and a border is not an outline. But the library's own accessibility
contract mandates a `focus-visible:ring-2` pattern for every interactive
component, and a ring is `outline`-based in Tailwind. **Every other library
component this product adopts is one `:focus { outline: 0 }` away from having no
visible focus indicator**, and no gate in either repo would report it.

**Ask (both cheap, first one cheapest).** Document the host prerequisite in the
consumer section next to the theme class, the fonts and the no-preflight rule:
a host must not neutralise `outline` globally, and here is the rule shape the
library relies on. Then decide whether the inset-border indicator is a
deliberate robustness property worth generalising.

**Product-side note.** The rule is old, broad, and not this migration's to
remove — deleting it changes focus rendering across the whole application. It is
flagged, not touched.

---

## 36. The shipped stylesheet carries only the utilities the library itself happens to use

Raised while converting the warm-up lot (the 8 SSO header panels), and it is
the same root cause that priced the asymmetric-padding question.

**Needed.** Two things the eight panels do today and must keep doing: a top
margin (`mt: 2` → 16px, `mt: 2.5` → 20px on one of them) and
`overflow: hidden`, which is load-bearing — it clips the inner title banner to
the surface's 4px radius. Neither is a padding, so neither belongs in the
`padding` prop.

**Today.** Measured against the installed `dist/index.css` at pin `a22b188`:

| class | in the shipped sheet |
|---|---|
| `overflow-hidden` | ✅ present |
| `mt-4` (16px) | ❌ **absent** |
| `mt-5` (20px) | ❌ **absent** |

So `overflow` could stay a class and the margin could not. This product does
not compile Tailwind — it consumes the pre-built sheet — so an absent class
resolves to nothing at all, silently. The margin is posed in `style` instead,
marked `FDS-WORKAROUND #36` in all four files.

**The same absence prices a design decision.** The per-side padding classes an
asymmetric `padding` API would need are present only where some library
component happens to use them:

| | 0 | 8 | 16 | 24 | 32 |
|---|---|---|---|---|---|
| `pt-` | ❌ | ❌ | ✅ | ❌ | ❌ |
| `pr-` | ❌ | ✅ | ✅ | ❌ | ✅ |
| `pb-` | ❌ | ✅ | ❌ | ❌ | ❌ |
| `pl-` | ❌ | ❌ | ✅ | ✅ | ✅ |

**8 of the 20 exist, by accident.** This is exactly the `p-8` situation before
#125 — a class the API would emit, absent from the sheet, resolving to 0px with
no error — multiplied by four sides. Any per-side padding API has to safelist
all 20 explicitly, the way `src/tokens/index.css` already safelists the five
`p-*`, and `paper-padding-emission.test.ts` has to assert all 20 compile.

**Ask.** Not "ship all of Tailwind". Two narrower things:

1. **Safelist the utilities the library's own public API can emit**, and pin
   them with the emission test. That is a closed, enumerable set — it is what
   #125 did for `p-8` — and it makes the sheet's contents a consequence of the
   API rather than of which component happened to use what.
2. **Say, in the consumer docs, that the sheet is not general-purpose.** A
   consuming agent's reasonable assumption is that a Tailwind-looking class
   works; the failure when it does not is silent and visual-only. One sentence
   plus the safelist list would close the whole class of bug — the same shape
   of ask as the `title`-is-not-a-slot documentation line in #33.

---

## 37. `Paper`'s title row cannot follow the host's text colour, and that blocks adoption

**Raised during the Paper pilot, from a measurement that changed the decision.**
Sandy's arbitration was to adopt `title`/`action`; this entry is why OpenCTI is
not adopting them yet.

**Needed.** OpenCTI's theme is customer-configurable per tenant, and
`theme_text_color` is one of the editable fields. Both of the product's panel
heading levels take it:

```ts
// ThemeDark.ts / ThemeLight.ts — typography
h3: { fontSize: 13, fontWeight: 400, fontFamily: 'Geologica', color: text_color, … }
h4: { fontSize: 12, fontWeight: 500, color: text_color, … }
```

`text_color` is the 9th argument of the theme factory — the tenant's
`theme_text_color`. A titled panel therefore follows the customer's text colour
today, on every screen.

**Today.** The library's title row paints `text-default-secondary`, a fixed
token. Measured at the DOM on three representative titles:

| | product `h4` | product `h3` | library `title` row |
|---|---|---|---|
| colour | `text_color` — **the customer's** | idem | **`--text-default-secondary`**, fixed |
| size / weight | 12px / 500 | 13px / 400 | 12px / 400 |
| family | IBM Plex Sans | **Geologica** | IBM Plex Sans |
| height | 15px | 15px | **24px** |
| rendered `text-transform` | `none` | `none` | `none` — identical |

**Consequence.** On a tenant with a customised `theme_text_color`, adopting
`title` makes every converted heading **stop following that colour**. That is
not a change of style — it is a **regression of a configured behaviour**, and it
is exactly the class of defect entry #28 raised for the surface colour and the
15%-border round then fixed for the border. The header is the third property of
the same component, and the only one still unreachable.

Worth noting what is NOT the problem: the typography differences above are real
but arbitrable, and the `text-transform` scare is not one — OpenCTI's theme
declares `lowercase` on `h3`/`h4` but `MuiTypography.styleOverrides.root` sets
`textTransform: 'none'` and wins, so the rendered text is identical on both
sides. Only the colour blocks.

**Ask.** Let the title row's colour be reachable by the host, the same way the
surface and the border already are — a per-layer base the host may re-declare,
or a documented custom property. The mechanism from #28 is already proven in
this product: re-declaring `--bg-elevation-default-layer-1` repaints the
surface, `--border-elevation-subtle-soft-layer-1` repaints the border. A
`--text-*` equivalent for the header row would close it.

**Removal test.** On a tenant whose `theme_text_color` differs from the default,
a `<Paper title="…">` header renders in that colour rather than in
`--text-default-secondary`. Until then OpenCTI keeps its own header above the
surface and does not pass `title`/`action`.

**Scope of what this unblocks, measured.** `Card.tsx` has **219 call sites**, and
**174 of them pass `title=`** — 79 %. So the `title`/`action` question and the
Card component question are **one decision, not two**: the day the header colour
is reachable, 174 sites become expressible in one move.

## 38. `Navbar` declares neither an anchoring inset nor a stacking level, so every host invents both

**Raised from a regression this pilot shipped and did not see.** Two defects were
reported on the running application after the wave closed. Both trace to the same
missing contract, and neither was visible to `tsc`, to eslint, to the build, to
the conformity gate or to the unit tests.

**What the component does today.** The `<nav>` it renders carries a background
and a width, and nothing else about where it sits in the page. It declares:

| | value shipped |
|---|---|
| `position` | none — the host must choose |
| horizontal inset | none |
| `z-index` | none (`auto`) |

**Why that is not neutral.** The rail is not an ordinary block: it is the
application's persistent shell. Two properties are load-bearing for it and for
no other component, so leaving them unset does not defer a style choice — it
defers a correctness requirement.

*Anchoring.* OpenCTI gave it `position: sticky` with a `top` inset (its own
rail-height workaround, #11). Sticky anchors only on the axes it is given an
inset for, so the rail held vertically and rode the horizontal scroll. Measured
drift, against a master build of the component it replaced:

| viewport | content overflow | legacy MUI Drawer paper | this component, `sticky` + `top` |
|---|---|---|---|
| 1024 | 376px | `fixed` — drift **0** | drift **−376px** — rail off screen |
| 1280 | 120px | `fixed` — drift **0** | drift **−120px** |
| 1440 | 0 | drift 0 | drift 0 |

*Stacking.* The legacy Drawer's paper painted at `z-index: 1200`. The `<nav>`
paints at `auto`, so a `z-index: 1` sibling wins. Four OpenCTI toolbars paint a
full-viewport background and offset only their content (`padding-left`); all four
declare `z-index: 1`. Measured with `elementFromPoint` at the centre of the rail:

| | legacy Drawer | this component |
|---|---|---|
| knowledge graph | rail wins the pixel | **bar wins** |
| container timeline | rail wins the pixel | **bar wins** |

**The signal is that the two hosts answered differently.** OpenAEV anchors its
rail with `position: fixed; left: 0` — measured drift 0, so it does not have the
anchoring defect. But its rail also paints at `z-index: auto`, so it carries the
same stacking gap; it is simply not reachable there, because OpenAEV has no
toolbar that aligns itself on the rail width (zero occurrences of a rail-width
offset in `openaev-front`). One missing contract, two different host answers, one
latent defect and one shipped regression.

**Asked.** Ship a documented default the host can override, rather than nothing:

1. a **stacking level** on the rail — ideally through a token in the same family
   as `--fds-z-overlay`, e.g. `--fds-z-navbar`, defaulting above ordinary
   application chrome and below overlays, so a host that needs a different order
   redeclares one custom property instead of reverse-engineering a value;
2. an **anchoring contract** — either the component anchors itself, or the
   documentation states which axes the host must pin and warns that a
   single-axis `sticky` leaves the other axis scrolling.

**Why it stayed invisible.** The value that mattered (`z-index: 1200`) lived on
the MUI Drawer that the migration deleted. Nothing carried it forward, and
nothing failed: the types are satisfied, the rendered rail is correct at any
viewport wide enough not to overflow, and the defect only appears below a
1400px-wide shell — a width no test exercises.

**Removal test.** Delete the `.app-navbar { left: 0; z-index: 1200 }` block from
`design-system-host.css`, load the knowledge graph of any container at a 1280px
viewport, scroll right: the rail must stay at the left edge and must keep the
pixel at its own centre. If it does, the workaround is retired.
