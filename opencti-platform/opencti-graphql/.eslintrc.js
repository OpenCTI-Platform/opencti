module.exports = {
  plugins: [
    '@typescript-eslint/eslint-plugin',
    'import-newlines'
  ],
  extends: [
    'airbnb-base',
    'airbnb-typescript/base',
    'plugin:import/recommended',
    'plugin:import/typescript',
    'plugin:@typescript-eslint/eslint-recommended',
    'plugin:@typescript-eslint/recommended'
  ],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2020,
    project: './tsconfig.json',
    tsconfigRootDir: __dirname
  },
  env: {
    jest: true
  },
  ignorePatterns: [
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
    'jest.relay.transform.js'
  ],
  rules: {
    'import/extensions': [
      'error',
      'ignorePackages',
      {
        js: 'never',
        ts: 'never'
      }
    ],
    'max-len': [
      'error',
      180,
      2,
      {
        ignoreUrls: true,
        ignoreComments: false,
        ignoreRegExpLiterals: true,
        ignoreStrings: true,
        ignoreTemplateLiterals: true
      }
    ],
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
        caughtErrorsIgnorePattern: '^_'
      }
    ],
    'import-newlines/enforce': ['error', { items: 20, 'max-len': 180 }],
    '@typescript-eslint/no-floating-promises': ['error'],
  },
  overrides: [
    {
      files: [
        '*.js'
      ],
      rules: {
        '@typescript-eslint/no-this-alias': 'off',
        '@typescript-eslint/return-await': 'off',
        '@typescript-eslint/no-use-before-define': 'off'
      }
    }
  ]
};
