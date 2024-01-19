module.exports = {
  extends: [
    'airbnb-base',
    'airbnb-typescript/base',
    'plugin:import/typescript',
    'plugin:@typescript-eslint/eslint-recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react/recommended',
  ],
  settings: {
    react: {
      version: 'detect',
    },
  },
  parserOptions: {
    ecmaVersion: 2020,
    project: './tsconfig.json',
    tsconfigRootDir: __dirname,
    parser: '@typescript-eslint/parser',
    ecmaFeatures: {
      jsx: true,
    },
  },
  env: {
    browser: true,
    jest: true,
  },
  overrides: [
    {
      files: ['*.jsx', '*.js', '*.ts', '*.tsx'],
    },
  ],
  ignorePatterns: [
    '**/builder/**',
    '**/coverage/**',
    '**/node_module/**',
    '**/packages/**',
    '**/src/generated/**',
    '**/__generated__/**',
    '**/src/static/ext/**',
    'jest.config.js',
    'jest.setup.js',
    'jest.file.transform.js',
    'jest.relay.transform.js',
    'extract-i18n-keyword.js',
    '**/test_e2e/**',
  ],
  plugins: [
    'import-newlines',
    'custom-rules',
  ],
  rules: {
    'custom-rules/classes-rule': 1,
    'no-restricted-syntax': 0,
    'react/no-unused-prop-types': 0,
    'react/prop-types': 0,
    'max-classes-per-file': ['error', 2],
    'object-curly-newline': 'off',
    'arrow-body-style': 'off',
    'max-len': [
      'error', 180, 2, {
        ignoreUrls: true,
        ignoreComments: false,
        ignoreRegExpLiterals: true,
        ignoreStrings: true,
        ignoreTemplateLiterals: true,
      },
    ],
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
    'react/jsx-indent': [2, 2],
    'react/jsx-indent-props': [2, 2],
    'react/jsx-closing-bracket-location': 'error',
  },
};
