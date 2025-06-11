/* eslint import/no-extraneous-dependencies: 0 */

import js from '@eslint/js';
import stylistic from '@stylistic/eslint-plugin';
import vitest from '@vitest/eslint-plugin';
import customRules from 'eslint-plugin-custom-rules';
import i18next from 'eslint-plugin-i18next';
import importPlugin from 'eslint-plugin-import';
import playwright from 'eslint-plugin-playwright';
import react from 'eslint-plugin-react';
import reactRefresh from 'eslint-plugin-react-refresh';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import globals from 'globals';
import ts from 'typescript-eslint';
import importNewlines from 'eslint-plugin-import-newlines';

export default [
  // rules recommended by @eslint/js
  js.configs.recommended,

  // rules recommended by typescript-eslint
  ...ts.configs.recommended,

  // rules recommended by eslint-plugin-react
  react.configs.flat.recommended,
  react.configs.flat['jsx-runtime'],
  {settings: {react: {version: 'detect'}}},

  // rules recommended by eslint-plugin-import
  importPlugin.flatConfigs.recommended,
  importPlugin.flatConfigs.typescript,
  {
    settings: {
      'import/resolver': 'oxc',
      'import/ignore': [
        'react-apexcharts', // ignore react-apexcharts as the default export is broken
      ],
    },
  },

  // rules recommended by @stylistic/eslint-plugin
  stylistic.configs.customize({semi: true}),

  // rules recommended by eslint-plugin-i18next
  i18next.configs['flat/recommended'],

  // other config

  // Main configuration
  {
    plugins: {
      'react-refresh': reactRefresh,
      'simple-import-sort': simpleImportSort,
      'custom-rules': customRules,
      'import-newlines': importNewlines,
      '@typescript-eslint': ts.plugin,
      'react': react,
      'import': importPlugin,
    },
    settings: {
      react: {version: 'detect'},
      'import/resolver': 'oxc',
      'import/ignore': ['react-apexcharts'],
    },
    rules: {
      // React rules
      'react-refresh/only-export-components': ['warn', {allowConstantExport: true}],
      'react/prop-types': 0,
      'react/no-unused-prop-types': 0,
      'react/jsx-indent': [2, 2],
      'react/jsx-indent-props': [2, 2],
      'react/jsx-closing-bracket-location': 'error',

      // Import rules
      'simple-import-sort/imports': 'error',
      'simple-import-sort/exports': 'error',
      'import-newlines/enforce': ['error', {items: 20, 'max-len': 180}],
      'import/no-named-as-default-member': 'off',
      'import/prefer-default-export': 'error',
      'import/no-mutable-exports': 'error',
      'import/namespace': 'off',
      'import/no-extraneous-dependencies': [
        'error',
        {
          devDependencies: [
            'src/utils/tests/*.{ts,tsx}',
            '**/*.test.{ts,tsx}',
            'tests_e2e/**/*.{ts,tsx,js}',
            'vite.config.ts',
            'vitest.config.ts',
            'playwright.config.ts',
          ],
          optionalDependencies: false,
        },
      ],

      // TypeScript rules
      '@typescript-eslint/naming-convention': ['error', {
        selector: 'variable',
        format: ['camelCase', 'UPPER_CASE'],
        leadingUnderscore: 'allow',
        trailingUnderscore: 'allow',
        filter: {
          regex: '/([^_]*)/',
          match: true,
        },
      }],
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/no-use-before-define': 'error',
      '@typescript-eslint/consistent-type-imports': ['error', {fixStyle: 'inline-type-imports'}],
      '@typescript-eslint/lines-between-class-members': 'off',

      // Stylistic rules
      '@stylistic/brace-style': ['error', '1tbs', {allowSingleLine: true}],
      '@stylistic/multiline-ternary': ['error', 'always-multiline', {ignoreJSX: true}],
      '@stylistic/object-curly-newline': ['error', {multiline: true}],
      '@stylistic/object-property-newline': ['error', {allowAllPropertiesOnSameLine: false}],

      // Custom rules
      'custom-rules/classes-rule': 1,
      'max-classes-per-file': ['error', 2],
      'object-curly-newline': 'off',
      'arrow-body-style': 'off',
      'no-restricted-syntax': 0,
      'sort-imports': 'off',
      'no-underscore-dangle': 'error',
      'no-await-in-loop': 'error',
      'no-param-reassign': 'error',
      'consistent-return': 'error',
      'default-case': 'error',
      'no-template-curly-in-string': 'error',
      'no-bitwise': 'error',
      'no-nested-ternary': 'error',
      'prefer-promise-reject-errors': 'error',
      'no-console': 'error',
      'max-len': [
        'error', 180, 2, {
          ignoreUrls: true,
          ignoreComments: false,
          ignoreRegExpLiterals: true,
          ignoreStrings: true,
          ignoreTemplateLiterals: true,
        },
      ],
      'no-restricted-imports': [
        'error', {
          patterns: [
            {
              group: [
                '@mui/material/*', '!@mui/material/locale', '!@mui/material/styles', '!@mui/material/colors', '!@mui/material/transitions',
                '@mui/x-date-pickers/*', '!@mui/x-date-pickers/AdapterDateFns',
                '@mui/icons-material/*',
                '@mui/lab/*',
              ],
              message: 'Please use named import from @mui/* instead.',
            },
          ],
          paths: [
            {
              name: 'react',
              importNames: ['*'],
              message: 'Do not use `import * as React from \'react\'`. Use `import {...} from \'react\'` instead.',
            },
          ],
        },
      ],
    },
    files: ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx'],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.commonjs,
        ...globals.es2020,
        ...globals.jest,
        process: true,
      },
      parserOptions: {
        ecmaVersion: 2020,
        project: './tsconfig.json',
        tsconfigRootDir: process.cwd(),
        ecmaFeatures: {
          jsx: true,
        },
      },
    },
    linterOptions: {reportUnusedDisableDirectives: 'off'},
  },

  // Unit tests config
  {
    files: ['src/__tests__/**/*'],
    plugins: {vitest},
    rules: {
      ...vitest.configs.recommended.rules,
      'import/no-extraneous-dependencies': [
        'error',
        {
          devDependencies: [
            '**/*.ts',
            '**/*.tsx',
          ],
        },
      ],
    },
  },

  // E2E tests config
  {
    files: ['tests_e2e/**/*'],
    ...playwright.configs['flat/recommended'],
    rules: {
      ...playwright.configs['flat/recommended'].rules,
      'import/no-extraneous-dependencies': [
        'error',
        {
          devDependencies: [
            '**/*.ts',
            '**/*.tsx',
          ],
        },
      ],
    },
  },

  // Ignore patterns
  {
    ignores: [
      'node_modules',
      'coverage',
      'packages',
      'public',
      'src/static/ext',
      'builder/prod/build',
      'builder/dev/build',
      '__generated__',
      'test-results',
      'playwright-report',
      'blob-report',
      'playwright/.cache',
      '.yarn',
      '**/builder/**',
      '**/src/generated/**',
      '**/__generated__/**',
      'jest.config.js',
      'jest.setup.js',
      'jest.file.transform.js',
      'jest.relay.transform.js',
      'extract-i18n-keyword.js',
      'playwright.config.ts',
    ],
  },
];