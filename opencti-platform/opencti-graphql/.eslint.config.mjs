// eslint.config.js
import { defineConfig } from 'eslint/config';
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';
import importPlugin from 'eslint-plugin-import';
import importNewlines from 'eslint-plugin-import-newlines';

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
        tsconfigRootDir: import.meta.dirname,
      },
			globals: {
        ...globals.node,
      },
    },

    rules: {
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
  }
]);
