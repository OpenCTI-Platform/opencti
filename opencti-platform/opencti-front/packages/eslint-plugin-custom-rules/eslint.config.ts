import { fileURLToPath } from 'node:url';
import { defineConfig } from 'eslint/config';
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';
import importPlugin from 'eslint-plugin-import';
import stylistic from '@stylistic/eslint-plugin';

export default defineConfig([
  eslint.configs.recommended,
  stylistic.configs.recommended,
  tseslint.configs.recommended,

  {
    plugins: {
      import: importPlugin,
      '@stylistic': stylistic,
    },
    rules: {
      ...importPlugin.configs.recommended.rules,
      ...importPlugin.configs.typescript.rules,
    },
    settings: {
      'import/resolver': {
        typescript: {
          project: './tsconfig.json',
        },
      },
    },
  },

  {
    files: ['**/*.{js,cjs,mjs,ts,cts,mts}'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: fileURLToPath(new URL('.', import.meta.url)),
      },
      globals: {
        ...globals.node,
      },
    },
    rules: {
      '@stylistic/brace-style': ['error', '1tbs'],
      '@stylistic/arrow-parens': ['error', 'always'],
      '@stylistic/space-before-blocks': 'error',
      '@stylistic/quote-props': ['error', 'as-needed'],
      '@stylistic/quotes': ['error', 'single', { avoidEscape: true }],
      '@stylistic/member-delimiter-style': ['error', { singleline: { requireLast: false } }],
      '@stylistic/semi': ['error', 'always'],
      '@stylistic/multiline-ternary': 'off',
      // Rule files import each other with a real `.ts` extension, which Node's ESM
      // resolver requires when it strips their types.
      'import/extensions': ['error', 'ignorePackages', { js: 'never', ts: 'always' }],
      // Nothing here ships: it is a lint plugin, loaded by the linter.
      'import/no-extraneous-dependencies': ['error', { devDependencies: true }],
    },
  },
]);
