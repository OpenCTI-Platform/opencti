import path from 'node:path';

// Deprecated components: the MUI / legacy `@filigran/ui` identifiers that have
// an equivalent already built in the Filigran Design System — i.e. every row
// marked `Lib status = done` in fds-migration/COMPONENT-MAPPING.md that has a
// MUI/legacy counterpart. Importing any of them from MUI / `@filigran/ui` is a
// regression; use the design-system component instead. Identifiers are grouped
// by their DS replacement. Keep in sync with COMPONENT-MAPPING.md (GENERATED).
const DEPRECATED_COMPONENTS = {
  Typography: 'Typography',
  Menu: 'Menu',
  MenuItem: 'Menu',
  MenuList: 'Menu',
  DropdownMenu: 'Menu',
  DropdownMenuContent: 'Menu',
  DropdownMenuItem: 'Menu',
  DropdownMenuLabel: 'Menu',
  DropdownMenuSeparator: 'Menu',
  DropdownMenuTrigger: 'Menu',
  Tooltip: 'Tooltip',
  TooltipContent: 'Tooltip',
  TooltipTrigger: 'Tooltip',
  TooltipProvider: 'Tooltip',
  IconButton: 'IconButton',
  Dialog: 'Dialog',
  DialogTitle: 'Dialog',
  DialogContent: 'Dialog',
  DialogContentText: 'Dialog',
  DialogActions: 'Dialog',
  AlertDialog: 'Dialog',
  AlertDialogAction: 'Dialog',
  AlertDialogCancel: 'Dialog',
  AlertDialogContent: 'Dialog',
  AlertDialogDescription: 'Dialog',
  AlertDialogFooter: 'Dialog',
  AlertDialogHeader: 'Dialog',
  AlertDialogTitle: 'Dialog',
  Select: 'Select',
  SelectContent: 'Select',
  SelectItem: 'Select',
  SelectTrigger: 'Select',
  SelectValue: 'Select',
  Switch: 'Switch',
  TextField: 'Input',
  Input: 'Input',
  InputAdornment: 'Input',
  Tabs: 'Tabs',
  Tab: 'Tabs',
  TabContext: 'Tabs',
  TabList: 'Tabs',
  TabPanel: 'Tabs',
  TabsList: 'Tabs',
  TabsTrigger: 'Tabs',
  Autocomplete: 'Combobox',
  Combobox: 'Combobox',
  MultiSelectFormField: 'Combobox',
  Radio: 'Radio',
  RadioGroup: 'Radio',
  Checkbox: 'Checkbox',
  AppBar: 'Header',
  Toolbar: 'Header',
  Button: 'Button',
  LoadingButton: 'Button',
  buttonVariants: 'Button',
  Slider: 'Slider',
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
