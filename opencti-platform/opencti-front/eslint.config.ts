import { fileURLToPath } from 'node:url';
import { defineConfig, includeIgnoreFile } from 'eslint/config';
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import react from 'eslint-plugin-react';
import globals from 'globals';
import importPlugin from 'eslint-plugin-import';
// @ts-expect-error -- eslint-plugin-import-newlines ships no type declarations.
import importNewlines from 'eslint-plugin-import-newlines';
import customRules from 'eslint-plugin-custom-rules';
import stylistic from '@stylistic/eslint-plugin';
import jsxA11y from 'eslint-plugin-jsx-a11y';

export default defineConfig([
  // Build and tool output is already named once, in `.gitignore`.
  includeIgnoreFile(fileURLToPath(new URL('.gitignore', import.meta.url))),

  {
    ignores: [
      // A workspace of its own: it carries its own ESLint, TypeScript and vitest
      // configuration, and its own commands.
      'packages/**',
      // Generated sources that git does track, so `.gitignore` does not cover them.
      '**/fds-tokens.generated.ts',
      '**/fds-tokens.generated.meta.json',
    ],
  },

  // Base JS rules
  eslint.configs.recommended,
  stylistic.configs.recommended,

  // Typescript rules
  tseslint.configs.recommended,

  // a11y rules
  {
    plugins: {
      'jsx-a11y': jsxA11y,
    },
    files: ['**/*.{ts,tsx,js,jsx}'],
    languageOptions: {
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
    },
    rules: {
      ...jsxA11y.configs.recommended.rules,
    },
    settings: {
      'jsx-a11y': {
        // Maps MUI components to semantic HTML tags
        components: {
          Button: 'button',
          IconButton: 'button',
          TextField: 'input',
          Select: 'select',
          Switch: 'input',
        },
      },
    },
  },

  // React rules
  {
    plugins: {
      react,
    },
    rules: {
      ...react.configs.recommended.rules,
    },
    settings: {
      react: {
        // temporary workaround for https://github.com/jsx-eslint/eslint-plugin-react/issues/3977
        version: '19.2',
      },
    },
  },

  // Import rules
  {
    plugins: {
      import: importPlugin,
    },
    rules: {
      ...importPlugin.configs.recommended.rules,
      ...importPlugin.configs.typescript.rules,
    },
  },

  // Additional plugins
  {
    plugins: {
      'import-newlines': importNewlines,
      'custom-rules': { rules: customRules },
      '@stylistic': stylistic,
    },
  },

  // Import resolver
  {
    settings: {
      'import/resolver': {
        typescript: {
          project: './tsconfig.json',
        },
        node: {
          extensions: ['.js', '.jsx', '.ts', '.tsx', '.d.ts'],
        },
      },
    },
  },

  // Custom rules (from legacy config)
  {
    files: ['**/*.{js,jsx,cjs,mjs,ts,tsx,cts,mts}'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        project: ['./tsconfig.front.json', './tsconfig.tool.json'],
        tsconfigRootDir: fileURLToPath(new URL('.', import.meta.url)),
        ecmaFeatures: { jsx: true },
      },
      globals: {
        ...globals.browser,
        ...globals.jest,
        myCustomGlobal: 'readonly',
      },
    },
    rules: {
      '@stylistic/jsx-curly-newline': 'off',
      '@stylistic/jsx-one-expression-per-line': 'off',
      '@stylistic/multiline-ternary': 'off',
      '@stylistic/brace-style': ['error', '1tbs'],
      '@stylistic/arrow-parens': ['error', 'always'],
      '@stylistic/space-before-blocks': 'error',
      '@stylistic/quote-props': ['error', 'as-needed'],
      '@stylistic/quotes': ['error', 'single', { avoidEscape: true }],
      '@stylistic/member-delimiter-style': ['error', { singleline: { requireLast: false } }],
      '@stylistic/semi': ['error', 'always'],
      'custom-rules/classes-rule': 1,
      'custom-rules/no-deprecated-components': 'warn',
      'custom-rules/no-replaced-components': 'error',
      'no-restricted-syntax': 0,
      'react/no-unused-prop-types': 0,
      'react/prop-types': 0,
      'max-classes-per-file': ['error', 2],
      'object-curly-newline': 'off',
      'arrow-body-style': 'off',
      'max-len': [
        'error',
        180,
        2,
        {
          ignoreUrls: true,
          ignoreComments: false,
          ignoreRegExpLiterals: true,
          ignoreStrings: true,
          ignoreTemplateLiterals: true,
        },
      ],
      '@typescript-eslint/lines-between-class-members': 'off',
      '@typescript-eslint/naming-convention': [
        'error',
        {
          selector: 'variable',
          format: ['camelCase', 'UPPER_CASE'],
          leadingUnderscore: 'allow',
          trailingUnderscore: 'allow',
          filter: {
            regex: '/([^_]*)/',
            match: true,
          },
        },
      ],
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      'import-newlines/enforce': ['error', { items: 20, 'max-len': 180 }],
      'import/no-extraneous-dependencies': [
        'error',
        {
          // includeTypes because `import type` of an undeclared package is skipped by default.
          includeTypes: true,
          devDependencies: [
            'src/utils/tests/*.{ts,tsx}',
            '**/*.test.{ts,tsx}',
            'tests_e2e/**/*.{ts,tsx,js}',
            // Build, test and lint configuration, plus the maintenance scripts and the
            // workspace package holding the custom ESLint rules: none of it ships.
            '*.ts',
            '*.d.ts',
            'script/**',
          ],
          optionalDependencies: false,
        },
      ],
      'react/jsx-closing-bracket-location': 'error',
      'react/react-in-jsx-scope': 'off',
    },
  },

  // Playwright fixtures and the maintenance scripts run in Node, not in a browser, so
  // they see Node's globals rather than the browser ones the app code is checked against.
  {
    files: ['tests_e2e/**', 'script/**'],
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
  },
]);
