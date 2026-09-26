import { fileURLToPath } from 'node:url';
import { defineConfig, includeIgnoreFile } from 'eslint/config';
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';
import importPlugin from 'eslint-plugin-import';
// @ts-expect-error -- eslint-plugin-import-newlines ships no type declarations.
import importNewlines from 'eslint-plugin-import-newlines';
import stylistic from '@stylistic/eslint-plugin';

export default defineConfig([
  // Build and tool output is already named once, in `.gitignore`: the shared artefacts
  // (build, dist, coverage, __generated__ ...) in the repository-root one, the rest here.
  includeIgnoreFile(fileURLToPath(new URL('../../.gitignore', import.meta.url))),
  includeIgnoreFile(fileURLToPath(new URL('.gitignore', import.meta.url))),

  {
    // Generated sources that git does track, so `.gitignore` does not cover them.
    ignores: [
      'src/generated/**',
      'src/stixpattern/**',
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
    files: ['**/*.{js,cjs,mjs,ts,cts,mts}'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        ecmaVersion: 2020,
        project: ['./tsconfig.back.json', './tsconfig.tool.json'],
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
      // includeTypes because `import type` of an undeclared package is skipped by default.
      'import/no-extraneous-dependencies': ['error', {
        includeTypes: true,
        devDependencies: [
          'tests/**',
          'script/**',
          'builder/**',
          // Every TypeScript file at the workspace root is configuration.
          '*.ts',
        ],
        optionalDependencies: false,
      }],
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
      'no-restricted-globals': ['error', {
        name: 'fetch',
        message: "Import fetch from 'undici' instead of using the global one, so requests and dispatchers share the same undici copy.",
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

  // Node runs these by stripping their types, and its ESM resolver needs the real
  // extension on a relative import — which the project-wide `ts: 'never'` forbids.
  {
    files: ['builder/**/*.{ts,cts}', 'knip.ts'],
    rules: {
      'import/extensions': ['error', 'ignorePackages', { js: 'never', ts: 'always' }],
    },
  },

  // The node-gyp-build shim is a genuine CommonJS module, bundled as such by esbuild,
  // and it reaches a specific file inside that package by name.
  {
    files: ['**/*.cts'],
    rules: {
      '@typescript-eslint/no-require-imports': 'off',
      'import/extensions': 'off',
    },
  },

  // The undici rule exists so the product's requests and dispatchers share one undici
  // copy. Tests and build scripts set up no dispatcher, so the global fetch is fine.
  {
    files: ['tests/**', 'script/**'],
    rules: {
      'no-restricted-globals': 'off',
    },
  },
]);
