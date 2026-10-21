import { fileURLToPath } from 'node:url';
import { defineConfig } from 'eslint/config';
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';
import importPlugin from 'eslint-plugin-import';
import importNewlines from 'eslint-plugin-import-newlines';
import stylistic from '@stylistic/eslint-plugin';

export default defineConfig([
  {
    ignores: [
      '**/build/**',
      '**/builder/**',
      '**/coverage/**',
      '**/node_module/**',
      '**/packages/**',
      '**/public/**',
      '**/static/**',
      '**/src/generated/**',
      '**/src/stixpattern/**',
      'jest.config.js',
      'jest.setup.js',
      'jest.file.transform.js',
      'jest.relay.transform.js',
    ],
  },

  // Base JS rules
  eslint.configs.recommended,
  stylistic.configs.recommended,

  // Typescript rules
  ...tseslint.configs.recommended,

  // Import plugin
  {
    plugins: {
      import: importPlugin,
    },
    settings: {
      'import/resolver': {
        typescript: {
          project: './tsconfig.json',
        },
        node: {
          extensions: ['.js', '.ts', '.d.ts'],
        },
      },
    },
  },

  // Additional plugins
  {
    plugins: {
      'import-newlines': importNewlines,
      '@stylistic': stylistic,
    },
  },

  // Global rules
  {
    files: ['**/*.ts', '**/*.js'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        ecmaVersion: 2020,
        project: './tsconfig.json',
        tsconfigRootDir: fileURLToPath(new URL('.', import.meta.url)),
      },
      globals: {
        ...globals.node,
      },
    },

    rules: {
      '@stylistic/multiline-ternary': 'off',
      '@stylistic/brace-style': ['error', '1tbs'],
      '@stylistic/arrow-parens': ['error', 'always'],
      '@stylistic/space-before-blocks': 'error',
      '@stylistic/quote-props': ['error', 'as-needed'],
      '@stylistic/quotes': ['error', 'single', { avoidEscape: true }],
      '@stylistic/member-delimiter-style': ['error', { singleline: { requireLast: false } }],
      '@stylistic/semi': ['error', 'always'],
      'import/extensions': [
        'error',
        'ignorePackages',
        { js: 'never', ts: 'never' },
      ],
      'max-len': ['error', 180, 2, {
        ignoreUrls: true,
        ignoreComments: false,
        ignoreRegExpLiterals: true,
        ignoreStrings: true,
        ignoreTemplateLiterals: true,
      }],
      camelcase: 'off',
      'no-underscore-dangle': 'off',
      'no-await-in-loop': 'off',
      'import/no-import-module-exports': 'off',
      'import/prefer-default-export': 'off',
      'arrow-body-style': 'off',
      'object-curly-newline': 'off',

      '@typescript-eslint/naming-convention': 'off',
      '@typescript-eslint/comma-dangle': 'off',
      '@typescript-eslint/no-explicit-any': 'off',

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
      '@typescript-eslint/no-floating-promises': 'error',
      'no-restricted-syntax': ['error', {
        selector: "CallExpression[callee.object.name=/^(res|response)$/][callee.property.name=/^(set|header)$/][arguments.length=1][arguments.0.type='ObjectExpression']",
        message: 'Use res.set(field, value) instead: the object form iterates with for...in and would also set headers from polluted prototype properties.',
      }],
    },
  },

  // JS-specific override
  {
    files: ['*.js'],
    rules: {
      '@typescript-eslint/no-this-alias': 'off',
      '@typescript-eslint/return-await': 'off',
      '@typescript-eslint/no-use-before-define': 'off',
    },
  },
]);
