# Styling (MUI)

- Stick to the theme provided by OpenCTI.
- **New code**: prefer the `sx` prop for inline styles or `styled()` for reusable styled components.
- **Legacy code**: many files still use `makeStyles` from `@mui/styles` — leave it in place when editing those files, do not migrate.
- Ensure dark mode compatibility (OpenCTI is heavily dark-mode focused).
