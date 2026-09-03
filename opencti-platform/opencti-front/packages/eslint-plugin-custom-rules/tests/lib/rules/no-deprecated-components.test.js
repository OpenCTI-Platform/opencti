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

ruleTester.run('no-deprecated-components', rule, {
  valid: [
    // Design-system imports are the target, never flagged.
    {
      code: `import { Button, Tooltip } from '@filigran/design-system';`,
    },
    // Unrelated third-party import.
    {
      code: `import { useState } from 'react';`,
    },
    // A non-deprecated identifier imported from MUI.
    {
      code: `import { SomethingNotDeprecated } from '@mui/material';`,
    },
  ],

  invalid: [
    // Named import of a deprecated MUI component.
    {
      code: `import { Button } from '@mui/material';`,
      errors: [{ messageId: 'deprecated' }],
    },
    // Default import: symbol resolved from the module path.
    {
      code: `import Tooltip from '@mui/material/Tooltip';`,
      errors: [{ messageId: 'deprecated' }],
    },
    // Legacy filigran-ui identifier is deprecated too.
    {
      code: `import { DropdownMenu } from '@filigran/ui';`,
      errors: [{ messageId: 'deprecated' }],
    },
    // Multiple deprecated identifiers in one statement.
    {
      code: `import { Select, Checkbox } from '@mui/material';`,
      errors: [{ messageId: 'deprecated' }, { messageId: 'deprecated' }],
    },
  ],
});
