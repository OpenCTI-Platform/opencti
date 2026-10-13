# Accessibility

`eslint-plugin-jsx-a11y`'s recommended rules run in `yarn lint`, and the frontend
quality CI fails on them. The patterns below keep the lint green without silencing
it. The helpers they name live in `src/utils/domEvent.ts`.

## Clickable means a button or a link

- Never put `onClick` on a `<div>` or `<span>`. Use `Button` / `IconButton` for an
  action and a link for navigation: both are focusable, keyboard-operable and
  announced correctly with no extra code.
- Where an element must keep `role="button"`, give it a tab stop and the
  Enter/Space activation of a native button:

  ```tsx
  <span role="button" tabIndex={0} onClick={() => sortBy(field)} onKeyDown={onActivationKey(() => sortBy(field))}>
  ```

- Where the content itself is the control (an image, a truncated value) and the
  design system's `Button` would paint a box around it, use a bare
  `<button type="button">` with the `FDS-WORKAROUND #67` marker
  (see `fds-migration/LIBRARY-FEEDBACK.md`).
- A read-only state is plain text, not a button that does nothing: render no
  button, or disable it, when there is no handler.

## Actions inside clickable rows and cards

- Stop the action's clicks from reaching the row or card with
  `stopLinkNavigation`, on both `onClick` and `onAuxClick` (a middle click only
  fires `auxclick`), on the action's container:

  ```tsx
  <Box onClick={stopLinkNavigation} onAuxClick={stopLinkNavigation}>
  ```

- Do **not** block the row with capture-phase handlers (`onClickCapture`): they run
  before the nested button's own handler and swallow it, so its menu stops opening.
- `DataTable` rows already ignore clicks bubbling from the dialogs, menus and
  drawers an action opens (`isRowTarget`), so those need no wrapper.
- An element that navigates but cannot be an anchor (a chip) uses
  `navigationClickHandlers(path, navigate)`, which keeps ctrl/cmd-click and
  middle-click opening a new tab.

## Focus: no `autoFocus`

`jsx-a11y/no-autofocus` forbids it, and `TextField` drops it from its props type.
Move focus explicitly, when the user's action calls for it, never on page load:

- **Dialog**: focus once the open transition has finished.

  ```tsx
  const nameInputRef = useRef<HTMLInputElement | null>(null);
  <Dialog slotProps={{ transition: { onEntered: () => nameInputRef.current?.focus() } }}>
    <Input ref={nameInputRef} ... />
  ```

- **Formik field** (`<Field component={TextField}>`): get the input through
  `innerRef`, since Formik does not turn `ref` into a real ref for a custom component.
- **Elsewhere** (a step that appears after a choice): a ref and a `useEffect` on the
  state that shows it.
- When an inline field or popover closes with the focus inside it, give the focus
  back to the control that opened it, or keyboard users land on `<body>`
  (see `WorkspaceHeaderTagManager.tsx`). Escape should close it.

## Accessible names

- Every icon-only button needs an `aria-label`, translated with `t_i18n`.
- Every image needs an `alt`. When an image is wrapped in a button, fall back to a
  label for an empty `alt`, or the button has no name.
- The design system's `Select` and `Combobox` need an accessible name too (a
  `SelectLabel` / `ComboboxLabel`, or an `aria-label`):
  `fds-migration/scripts/check-accessible-names.mjs` checks them in CI, as jsx-a11y
  cannot see into the library's compound components.

## Tooltips

- A disabled button cannot trigger its own tooltip. Reuse `DisabledReasonTooltip`
  (`FDS-WORKAROUND #68`), which puts a focusable wrapper around it.
- Do not put information **only** in a tooltip on something that cannot take focus:
  keyboard users never see it. Show it inline or behind a real button.

## When a rule does not apply

- Disable it on the exact line, with a comment saying why:

  ```tsx
  // `role` is EntityStixCoreRelationships' own prop, the relationship
  // role it filters on (toRole/fromRole), not an ARIA role.
  // eslint-disable-next-line jsx-a11y/aria-role
  ```

- Never disable a jsx-a11y rule for a whole file, except in test fixtures.
- When the cause is a design-system gap, record it in
  `fds-migration/LIBRARY-FEEDBACK.md` and mark the site `FDS-WORKAROUND #N`.
- Only `Button` and `IconButton` are mapped to a native element (`<button>`) in
  `eslint.config.ts`. Map a component only if every component of that name renders
  that element: the mapping matches by JSX name, not import source.

## Tests

When you change an interactive component, test its keyboard path, not only the click:

```tsx
const { user } = testRender(<TruncatedRawValue value={LONG_VALUE} variant="text" />); // src/utils/tests/test-render
await user.tab();
await user.keyboard('{Enter}');
```

See `TruncatedRawValue.test.tsx` or `BasicFilterInput.test.tsx`.
