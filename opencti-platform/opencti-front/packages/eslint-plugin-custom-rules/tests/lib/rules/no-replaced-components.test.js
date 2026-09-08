import rule from '../../../lib/rules/no-replaced-components';
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

ruleTester.run('no-replaced-components', rule, {
  valid: [
    // Design-system imports are the target, never flagged.
    {
      code: imp('{ Paper, Breadcrumbs }', DS),
    },
    // Unrelated third-party import.
    {
      code: imp('{ useState }', 'react'),
    },
    // A component that is only deprecated (warning), not fully replaced.
    {
      code: imp('{ Button }', MUI),
    },
  ],

  invalid: [
    // Named import of a fully replaced MUI component.
    {
      code: imp('{ Paper }', MUI),
      errors: [{ messageId: 'replaced' }],
    },
    // Default import: symbol resolved from the module path.
    {
      code: imp('Paper', `${MUI}/Paper`),
      errors: [{ messageId: 'replaced' }],
    },
    // Breadcrumbs family.
    {
      code: imp('{ Breadcrumbs, BreadcrumbItem }', MUI),
      errors: [{ messageId: 'replaced' }, { messageId: 'replaced' }],
    },
    // Legacy filigran-ui Navbar family.
    {
      code: imp('{ Navbar, NavbarItem, NavbarSubmenu }', FILIGRAN_UI),
      errors: [{ messageId: 'replaced' }, { messageId: 'replaced' }, { messageId: 'replaced' }],
    },
  ],
});
