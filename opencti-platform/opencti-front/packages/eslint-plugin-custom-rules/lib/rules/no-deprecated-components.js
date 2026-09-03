import path from 'node:path';

// Deprecated components: the MUI / legacy `@filigran/ui` identifiers whose
// Filigran Design System replacement is already finished AND in service in
// OpenCTI. Only those are enforced — importing them from MUI / `@filigran/ui`
// is now a regression. Source of truth is the `enforced` map in
// fds-migration/mui-regression-policy.generated.json (a GENERATED file); keep
// this list in sync with it. Components whose replacement is not ready yet
// (`held` / `notGatable` in that policy) are intentionally excluded.
const DEPRECATED_COMPONENTS = {
  Button: 'Button',
  LoadingButton: 'Button',
  buttonVariants: 'Button',
  Tooltip: 'Tooltip',
  TooltipContent: 'Tooltip',
  TooltipTrigger: 'Tooltip',
  TooltipProvider: 'Tooltip',
  IconButton: 'IconButton',
  Badge: 'Badge',
  TextField: 'Input',
  Input: 'Input',
  InputAdornment: 'Input',
  Textarea: 'Textarea',
  Switch: 'Switch',
  Select: 'Select',
  SelectContent: 'Select',
  SelectItem: 'Select',
  SelectTrigger: 'Select',
  SelectValue: 'Select',
  Checkbox: 'Checkbox',
  Radio: 'Radio',
  RadioGroup: 'Radio',
  Autocomplete: 'Combobox',
  Combobox: 'Combobox',
  MultiSelectFormField: 'Combobox',
  Chip: 'Chip',
  Paper: 'Paper',
  Menu: 'Menu',
  MenuItem: 'Menu',
  MenuList: 'Menu',
  DropdownMenu: 'Menu',
  DropdownMenuContent: 'Menu',
  DropdownMenuItem: 'Menu',
  DropdownMenuLabel: 'Menu',
  DropdownMenuSeparator: 'Menu',
  DropdownMenuTrigger: 'Menu',
  ButtonGroup: 'ButtonGroup',
  ToggleButton: 'ButtonGroup',
  ToggleButtonGroup: 'ButtonGroup',
  AppBar: 'Header',
  Toolbar: 'Header',
  CircularProgress: 'Spinner',
};

// Same import sources the MUI regression gate watches
// (fds-migration/scripts/check-mui-regression.mjs).
const DEPRECATED_SOURCE_RE = /^@mui\/|^@filigran\/ui(\/|$)/;

const rule = {
  meta: {
    type: 'problem',
    docs: {
      description: 'Disallow using components deprecated by the Filigran Design System (see fds-migration/COMPONENT-MAPPING.md)',
    },
    schema: [],
    messages: {
      deprecated: '`{{ identifier }}` is deprecated; use the Filigran Design System `{{ replacement }}` from \'@filigran/design-system\' instead. See fds-migration/COMPONENT-MAPPING.md.',
    },
  },
  create: (context) => {
    return {
      ImportDeclaration(node) {
        const source = node.source.value;
        if (typeof source !== 'string' || !DEPRECATED_SOURCE_RE.test(source)) {
          return;
        }
        for (const specifier of node.specifiers) {
          let identifier = null;
          if (specifier.type === 'ImportSpecifier') {
            identifier = specifier.imported.name;
          } else if (specifier.type === 'ImportDefaultSpecifier') {
            // A default import carries no symbol name at the source, so the
            // module's own last path segment is the component:
            // '@mui/material/Button' -> Button.
            identifier = path.posix.basename(source);
          }
          if (identifier && Object.prototype.hasOwnProperty.call(DEPRECATED_COMPONENTS, identifier)) {
            context.report({
              node: specifier,
              messageId: 'deprecated',
              data: {
                identifier,
                replacement: DEPRECATED_COMPONENTS[identifier],
              },
            });
          }
        }
      },
    };
  },
};

export default rule;
