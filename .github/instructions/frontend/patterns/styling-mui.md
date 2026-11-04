# Styling (MUI)

> Applies to code that is legitimately still on MUI. Before adding a MUI
> component at all, read `AGENTS.md` at the repository root: where the design
> system already ships the component, using it is mandatory and a CI gate
> enforces it.

- Stick to the theme provided by OpenCTI.
- Use the `sx` prop for inline styles or `styled()` from `@mui/material/styles` for reusable styled components.
- Read the theme with `useTheme` from `@mui/material/styles`.
- In `sx`, read theme values through tokens (`color: 'grey.700'`, `marginLeft: 2`) rather than `(theme) => ...` callbacks.
- Ensure dark mode compatibility (OpenCTI is heavily dark-mode focused).
