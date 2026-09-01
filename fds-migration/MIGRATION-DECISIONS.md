# Migration decisions — OpenCTI

Why a migration choice was made, moved out of the product source.

Each section is the long form of a decision taken while replacing MUI with
`@filigran/design-system`. The source file keeps at most a one-line pointer to
the anchor here, so a reader of the code is never made to read the migration's
reasoning to understand the statement in front of them.

**This file is cited by product code.** Every section below is the target of a
`see fds-migration/MIGRATION-DECISIONS.md#<anchor>` comment in the file named
under it — that citation is what keeps it alive under the repo's doc rule. Find
the citations with:

```bash
git grep -n "MIGRATION-DECISIONS.md#"
```

A section whose citation is gone should be deleted with it. Library *gaps* do
not belong here: they go to `LIBRARY-FEEDBACK.md`, and a workaround in the code
keeps its `FDS-WORKAROUND #N` marker pointing there.

---

## breadcrumb-underline

`src/components/Breadcrumbs.hostCss.test.ts` — locks FDS-WORKAROUND #40.

The library ships `.underline` as an UNLAYERED utility, so the cascade is
settled by specificity alone. At rest `.underline` (0,1,0) beats this product's
global `a` reset (0,0,1). On hover and on focus it loses, because `a:hover` /
`a:focus` are (0,1,1) — one pseudo-class above the utility — and the shorthand
`text-decoration: none` takes the line away. The host rule scopes the fix to the
landmark, which puts it at (1,1,1) and back in front.

Neither repository can see that on its own: the library's gates never load a
product stylesheet, and no product gate reads the library's. So the guard reads
BOTH — the served `index.css` from the installed package and this product's own
global sheets — and settles the cascade the way a browser would: specificity
first, load order only as the tie-break, with the order itself read from
`front.tsx` rather than assumed.

It is a static guard. What proves the RENDERING is the browser measurement in
`LIBRARY-FEEDBACK.md` #40, taken against two separate CSS builds — with and
without the block — because the first attempt at that proof disabled a rule
through `cssRules`, which is inaccessible under `file://`, and so measured
nothing at all. jsdom cannot stand in for it: it resolves no cascade for
`:hover`.

## dialog-padding-keys

`src/components/common/dialog/Dialog.tsx` — why the padding fix is not neutral.

The keys are `py`/`px`, not `pY`/`pX`. MUI's system keys are lower-case, so the
previous spelling was dropped silently and every dialog fell back to
`DialogContent`'s own `padding: 20px 24px`.

Net effect of that first fix, measured against the installed MUI source:
horizontal unchanged (24px either way), the top already 0 for a titled dialog
(`.MuiDialogTitle-root + & { paddingTop: 0 }`), so what moved was the BOTTOM —
20px to 0, and a dialog with no title lost its 20px top too.

**Superseded once since.** `py: 0` clipped the focus ring: this element scrolls,
and the library paints the ring 4px OUTSIDE the field, so a field flush with the
edge lost it. The padding is now given back and taken out of the layout again —
`'&&': { py: '4px', my: '-4px' }`. The `&&` is required because
`.MuiDialogTitle-root + &` outranks a plain `sx`, which is the same
specificity trap the lower-case keys above belong to.

## filter-value-checkbox-role

`src/components/filters/FilterChipPopover.tsx` — why this box is not
`presentational` while every other converted box is.

The row IS a `role="option"` in MUI's Autocomplete listbox, so a real control
nested in it is an axe `nested-interactive` finding. That finding predates the
conversion — the box here was already a real MUI Checkbox — and `presentational`
renders an unfocusable `<span>`, which removes the checkbox role that
`tests_e2e/model/filters.pageModel` uses to pick a filter value.

Clearing the nesting means changing this markup and that page model together, so
it is parked rather than half-done.

## ee-badge-inside-button

`src/private/components/chatbox/AskArianeButton.tsx` — the EE badge sits inside
the button, in its trailing slot.

This reverses the earlier "sibling at a 4px gap" ruling, at the designer's
explicit request. `clickable={false}` is what makes it legal: the chip renders a
plain element rather than the `<button>` it defaults to, so the surrounding
control keeps owning the click and no button is nested inside another. The slot
brings its own gap, so the chip's default inline-start margin is zeroed.

## switch-formgroup-wrapper

`src/components/fields/SwitchField.jsx` — what was kept and what was dropped.

`FormGroup` and the fit-content wrapper are kept so the control holds the row
position it had under MUI. `FormControlLabel` is gone because the library Switch
carries its own label — NOT because this file was exposed to the
clone-injection trap: the old code put `checked` and `onChange` on the MuiSwitch
child, so `FormControlLabel` had nothing to inject. That mechanism is real (it
broke the consent checkbox in #17946); it simply was not active here.

## add-filter-picker

`src/private/components/common/lists/ListFilters.tsx` — the two deliberate
omissions on the Add-filter Combobox.

**No held value.** Choosing an option adds a filter and the field goes straight
back to empty, which is why `value` is a literal `null` rather than state.

**No `<ComboboxLabel>`.** `placeholder` carries the name instead. The library
renders a label ABOVE the control, and this control sits in a flex row beside
the unlabelled search field — a label here would make it the only tall item in
the row and re-open the very alignment defect the same pass fixed. The
accessible name stays on the input.

**No `aria-label` on the trigger.** Naming the trigger after the field too gave
TWO elements the accessible name "Add filter" — the input and the chevron — and
`getByLabel('Add filter')` in `filters.pageModel` then failed strict mode. The
library already names it "Toggle options", which is what every other converted
Combobox in this product relies on.

## bookmarks-sibling-title

`src/private/components/common/stix_domain_objects/StixDomainObjectBookmarks.jsx`
— why the entity-cards title lives here.

Same shape as "Favorite entities", 16px below the favourite cards and 8px above
the entity cards it labels. It lives in this component rather than in the five
`*Cards` pages because this component already renders nothing when there are no
favourites: the title then appears exactly when the block it belongs under does,
and the two spacings stay in one place.

## topbar-search-not-headersearch

`src/private/components/nav/TopBar.tsx` — why the bar does not use
`HeaderSearch`.

`HeaderSearch` (library #189) was built for exactly this bar, and is parked at
pin `1f7c64c` — see `LIBRARY-FEEDBACK.md` #54. The NLQ toggle is a split button
and `HeaderSearchMode` renders one plain `<button>` per entry; passing the caret
through `icon` would nest an interactive element inside that button, which is
the axe `nested-interactive` failure the library avoided on the Select clear.

`grow` caps below this bar's ceiling — `LIBRARY-FEEDBACK.md` #17.

## authorized-members-select

`src/private/components/common/form/AuthorizedMembersField.tsx` and
`AuthorizedMembersFieldListItem.tsx` — why FDS-WORKAROUND #44 is a revert and
not a fix.

`tests_e2e/dashboardRestriction` became INTERMITTENT once the field was
converted — the same commit red on one run and green on the re-run, failing on
`getByRole('listbox', { name: 'Access right' }).getByText('can view')` with
"visible, enabled and stable" never satisfied.

Diagnosed at the pointer on the real access-restriction dialog and NOT
reproduced: the listbox opens correctly named, the option measures 97x32 with
`pointer-events: auto`, and `elementFromPoint` at its centre returns the option
itself. Cause unidentified, so this is a revert — an access-rights control does
not get carried forward on a green re-run.

The dialog stacks THREE Radix Selects (the field plus one per member row) beside
a MUI Autocomplete, which is the obvious place to look next.

## field-state-tint

`src/private/components/settings/sub_types/custom_views/CustomViewPreviewEntitySelector.tsx`
and `src/components/dashboard/DashboardRelativeDateSelect.tsx` —
FDS-WORKAROUND #43, waiting on a DESIGN decision rather than a library prop.

The first field tints its own border AND its label
(`designSystem.tertiary.orange.400`) while a preview entity is selected; the
second takes a `selectSx` border from `DashboardTimeFilters` while a relative
date is active. Both are product state signals on the field shell, not
decoration.

The library field owns its border and ships no per-state tint, and hardcoding
the colour is forbidden, so both conversions were made and reverted rather than
drop the signal. On the second site the designer looked for the 1px grey border
on the live screen and did not see it, so that marker is being redesigned rather
than ported.

## theme-background-select

`src/private/components/settings/themes/ThemeForm.tsx` — FDS-WORKAROUND #45 is
retired, and one difference is deliberately not arbitrated.

`clearable` landed in library #190, so the `endAdornment` that used to carry the
clear IconButton is gone and the library owns the control. The empty string is
still a real product state: clearing means "the login page keeps its default
panel".

`SelectValue` receives the mapped label as children, which keeps the trigger's
wording identical to MUI's `renderValue` — the option row reads "Image URL"
while the trigger reads "Add background image". This conversion does not
arbitrate that difference.

## elevation-layer-compensation

`src/utils/fdsLayer.ts` — why a layer class is not enough, and why the three
input aliases are re-declared beside it. Library gap: `LIBRARY-FEEDBACK.md` #57.

The page is layer 0, a panel over it layer 1, a panel inside that layer 2. The
library's `.layer-N` class re-declares the elevation aliases, but a `var()`
inside a custom-property declaration is substituted on the element that
DECLARES it — so `--bg-input-default`, declared once at the root, keeps the
layer-0 value however deep the class is applied. Measured on the shipped build:

| context | `--bg-elevation-highlight` | `--bg-input-default` |
|---|---|---|
| root (layer 0) | `#13213e` | `#13213e` |
| `.layer-2` alone | `#0c1527` | `#13213e` |
| `.layer-2` + re-declared | `#0c1527` | `#0c1527` |

Exactly three input tokens alias an elevation token; the rest of the family
aliases feedback and text tokens, which are layer-independent. The class and
`layerInputVars` must therefore sit on the SAME node.

**Filter popovers** are the one composite case: the surface is
`--bg-elevation-highlight` at layer 1 while the fields inside sit at layer 2.
Both halves live on the paper itself, so the surface must name its layer-1 value
explicitly — the layer-2 class it shares the node with has already moved the
ambient alias.

## theme-scope-root

`src/utils/hooks/useFdsThemeScope.ts` — why the theme class goes on the document
root, and what a customer paper colour can actually move.

**Root, not a container.** FDS portals its floating layers (flyouts, tooltips,
dropdowns) into `<body>`, outside whatever subtree rendered the component. A
container-scoped class themes the component and leaves every portalled layer
unthemed, and the defect only shows on hover or on a collapsed rail — exactly
where review does not look.

**Customer surface colour.** Overriding the semantic alias does nothing (same
substitution rule as
[elevation-layer-compensation](#elevation-layer-compensation)), so only the
per-layer BASE can be moved, border base included — the diluted variant is
derived from it, so re-declaring the diluted value directly would short-circuit
the 15% dilution. Layer 1 only: that is the Paper default elevation and the
customer supplies exactly one paper colour.

Accepted consequence: a 15% dilution of the surface colour over that same
surface composites back to the surface, so a customised install has no visible
edge on its panels. That is the arbitrated outcome, not a defect.

## light-theme-names

`src/utils/themeName.ts` — why two names mean "light".

Three consumers must never disagree: `themeBuilder` picks the MUI palette,
`useFdsThemeScope` writes the `.light`/`.dark` class the design-system
components resolve their custom properties against, and the body `data-theme`
attribute the product's own stylesheets target. When one of them answered
differently, the app rendered a light MUI surface with dark design-system tokens
on it.

Both light names are still in the wild:

- `Filigran Light`, the built-in shipped since the built-in-themes change;
- `Light`, the legacy name. Installations that had customised it keep it — the
  migration only renames a row it finds untouched, and demotes a customised one
  to a normal theme under its original name.

Anything else is dark, which is what `themeBuilder` has always done with custom
themes.

## builtin-theme-migration-order

`opencti-graphql/src/migrations/1787800000000-align-builtin-theme-rows-with-wcag-defaults.ts`
— why it runs before `1787822440159-add-filigran-built-in-themes`.

That migration compares each built-in row against the constants field by field
with a strict `===`. When they match it renames the row to `Filigran Dark` /
`Filigran Light`; when they do not, it seeds a second built-in row and demotes
the original. The design-system bridge moved these seeded defaults, so without
this pass every existing installation would take the second branch and end up
with four themes — the WCAG values never reaching the users who stay on the
original one. Aligning first makes the comparison succeed, so the rename is
clean and the WCAG values travel with the row.

**The row is judged as a whole before anything is written** (product ruling):
every field the downstream migration compares must still hold a value we
recognise as a default — the current one, or one of the historical ones it has
carried. One unrecognised value anywhere marks the row as customised and it is
skipped ENTIRELY, including the fields still on defaults. A half-aligned theme
is not a state anyone asked for, and such a row is exactly what the next
migration is meant to preserve and demote.

Only the fields whose SEEDED default moved need rewriting — the logo and
login-aside defaults did not move. Each records EVERY historical default it has
carried, because some moved more than once: `theme_secondary` on Light was
seeded as `#00BD94` and later as `#00f0bc`, and installations exist on both.
`theme_text_color` moved by letter case alone; rewriting it normalises the row
so the strict comparison downstream succeeds.

## fab-conversion-deferred

Nine floating action buttons across the product — the `<Fab>` mounts in
`Drawer.tsx`, `NoteCreation.tsx`, `IndicatorCreation.tsx`,
`StixCyberObservableCreation.jsx`, `ContainerAddStixCoreObjects.jsx`,
`StixCoreRelationshipCreationFromRelation.jsx`,
`StixCoreRelationshipCreationSelectEntityStage.tsx`,
`StixSightingRelationshipCreationFromEntity.jsx` and
`SubTypeWorkflowStatusAdd.tsx`.

They stay on MUI deliberately. Whether these keep their floating shape or are
rethought as in-page buttons is a product/UX call, not a mechanical conversion,
so the Button/Chip wave left all nine untouched. Pending decision, owner Sandy,
raised 2026-08-26.

Retire this section when the shape is decided: either the nine convert, or they
are ruled to stay and the markers come out.
