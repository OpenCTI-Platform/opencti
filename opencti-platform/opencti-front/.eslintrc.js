module.exports = {
  extends: [
    'airbnb-base',
    'airbnb-typescript/base',
    'plugin:import/typescript',
    'plugin:@typescript-eslint/eslint-recommended',
    'plugin:@typescript-eslint/recommended'
  ],
  parserOptions: {
    ecmaVersion: 2020,
    project: './tsconfig.json',
    tsconfigRootDir: __dirname
  },
  env: {
    browser: true,
    jest: true
  },
  ignorePatterns: [
    '**/builder/**',
    '**/coverage/**', 
    '**/node_module/**', 
    '**/packages/**', 
    '**/public/**', 
    '**/src/generated/**',
    '**/__generated__/**',
    '**/src/static/ext/**',
    'jest.config.js', 
    'jest.setup.js',
    'jest.file.transform.js',
    'jest.relay.transform.js'
  ],
  rules: {
    'no-restricted-syntax': 0,
    'react/no-unused-prop-types': 0,
    'react/prop-types': 0,
    'max-classes-per-file': ['error', 2],
    'object-curly-newline': 'off',
    'arrow-body-style': 'off',
    'max-len': [
      'error', 180, 2, {
        'ignoreUrls': true,
        'ignoreComments': false,
        'ignoreRegExpLiterals': true,
        'ignoreStrings': true,
        'ignoreTemplateLiterals': true
      }
    ],
    '@typescript-eslint/naming-convention': ['error', {
      'selector': 'variable',
      'format': ['camelCase', 'UPPER_CASE'],
      'leadingUnderscore': 'allow',
      'trailingUnderscore': 'allow',
      'filter': {
        'regex': '/([^_]*)/',
        'match': true
      }
    }],
    'no-unused-vars': 'off',
    '@typescript-eslint/no-unused-vars': [
      'error',
      {
        'argsIgnorePattern': '^_',
        'varsIgnorePattern': '^_',
        'caughtErrorsIgnorePattern': '^_'
      }
    ]
  }
}
