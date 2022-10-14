module.exports = {
  testEnvironment: 'node',
  testTimeout: 1200000,
  setupFilesAfterEnv: ['./jest/jest.setup.js'],
  testRegex: ['src/.*\\.test\\.(js|ts)$', 'tests/.*-test\\.(js|ts)$'],
  transform: {
    '\\.(js|ts)$': ['esbuild-jest', { sourcemap: true }],
    '\\.(gql|graphql)$': '@graphql-tools/jest-transform'
  },
  transformIgnorePatterns: ['node_modules/(?!set-interval-async|antlr4)'],
  reporters: ['default', ['jest-junit', { outputDirectory: './test-results/jest/', outputName: 'results.xml' }]],
  collectCoverageFrom: ['src/**/*.js', 'src/**/*.ts'],
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '/src/migrations',
    '/src/utils',
    '/src/stixpattern',
    '/src/config',
    '/src/database/indexing.js',
    '/src/database/migration.js',
    '/src/app.js',
    '/src/httpServer.js',
    '/src/index.js',
    '/src/indexer.js',
    '/src/initialization.js',
  ],
};
