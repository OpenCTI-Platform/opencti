import rule from '../../../lib/rules/no-deprecated-components';
import { RuleTester } from 'eslint';
import parser from '@typescript-eslint/parser';

const ruleTester = new RuleTester({
  parser,
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module',
  },
});

// Build import statements without writing a literal `from '@mui/...'` line, so
// the MUI regression gate (fds-migration/scripts/check-mui-regression.mjs) does
// not mistake these test fixtures for real MUI imports being introduced.
const imp = (what, source) => `import ${what} ${'from'} '${source}';`;
const MUI = '@mui/material';
const FILIGRAN_UI = '@filigran/ui';
const DS = '@filigran/design-system';

ruleTester.run('no-deprecated-components', rule, {
  valid: [
    // Design-system imports are the target, never flagged.
    {
      code: imp('{ Button, Tooltip }', DS),
    },
    // Unrelated third-party import.
    {
      code: imp('{ useState }', 'react'),
    },
    // A non-deprecated identifier imported from MUI.
    {
      code: imp('{ SomethingNotDeprecated }', MUI),
    },
  ],

  invalid: [
    // Named import of a deprecated MUI component.
    {
      code: imp('{ Button }', MUI),
      errors: [{ messageId: 'deprecated' }],
    },
    // Default import: symbol resolved from the module path.
    {
      code: imp('Tooltip', `${MUI}/Tooltip`),
      errors: [{ messageId: 'deprecated' }],
    },
    // Legacy filigran-ui identifier is deprecated too.
    {
      code: imp('{ DropdownMenu }', FILIGRAN_UI),
      errors: [{ messageId: 'deprecated' }],
    },
    // Multiple deprecated identifiers in one statement.
    {
      code: imp('{ Select, Checkbox }', MUI),
      errors: [{ messageId: 'deprecated' }, { messageId: 'deprecated' }],
    },
  ],
});
