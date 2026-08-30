# Styling (MUI)

> Applies to code that is legitimately still on MUI. Before adding a MUI
> component at all, read `AGENTS.md` at the repository root: where the design
> system already ships the component, using it is mandatory and a CI gate
> enforces it.

- Stick to the theme provided by OpenCTI.
- **New MUI code**: prefer the `sx` prop for inline styles or `styled()` for reusable styled components.
- **Legacy code**: many files still use `makeStyles` from `@mui/styles` — leave it in place when editing those files, do not migrate.
- Ensure dark mode compatibility (OpenCTI is heavily dark-mode focused).
