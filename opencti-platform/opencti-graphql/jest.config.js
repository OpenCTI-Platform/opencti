module.exports = {
  testEnvironment: 'node',
  setupFilesAfterEnv: ['./jest.setup.js'],
  testRegex: 'tests/.*-test.js$',
  transform: {
    '\\.js$': ['babel-jest'],
    '\\.graphql$': 'jest-transform-graphql',
  },
  reporters: ['default', ['jest-junit', { outputDirectory: './test-results/jest/', outputName: 'results.xml' }]],
  collectCoverageFrom: ['src/**/*.js'],
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '/src/migrations',
    '/src/utils',
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
