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

## 19. No `Badge`

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

**Pending.** The library is replacing the `tone` axis with `severity="ee"` and a
new visual. At the next pin bump, switch the word and re-checkpoint the bar.

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
