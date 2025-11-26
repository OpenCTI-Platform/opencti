import { defineConfig } from 'eslint/config';
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import react from 'eslint-plugin-react';
import globals from 'globals';
import importPlugin from 'eslint-plugin-import';
import importNewlines from 'eslint-plugin-import-newlines';
import customRules from 'eslint-plugin-custom-rules';

export default defineConfig([
  {
    ignores: [
      '**/builder/**',
      '**/coverage/**',
      '**/node_module/**',
      '**/packages/**',
      '**/src/generated/**',
      '**/__generated__/**',
      '**/src/static/ext/**',
      'extract-i18n-keyword.js',
      'playwright.config.ts',
      'vite.config.mts',
      'vitest.config.ts',
      'setup-vitest.ts',
    ],
  },

  // Base JS rules
  eslint.configs.recommended,

  // Typescript rules
  tseslint.configs.recommended,

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
        version: 'detect',
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
      'custom-rules': customRules,
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
    files: ['**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname,
        ecmaFeatures: { jsx: true },
      },
			globals: {
				...globals.browser,
				...globals.jest,
				myCustomGlobal: "readonly",
			},
    },
    rules: {
      'custom-rules/classes-rule': 1,
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
          devDependencies: [
            'src/utils/tests/*.{ts,tsx}',
            '**/*.test.{ts,tsx}',
            'tests_e2e/**/*.{ts,tsx,js}',
          ],
          optionalDependencies: false,
        },
      ],
      'react/jsx-indent': [2, 2],
      'react/jsx-indent-props': [2, 2],
      'react/jsx-closing-bracket-location': 'error',
      'react/react-in-jsx-scope': 'off',
    },
  },
]);
