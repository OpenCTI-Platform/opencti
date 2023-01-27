module.exports = {
  testEnvironment: 'node',
  setupFilesAfterEnv: ['./jest.setup.js'],
  testRegex: 'tests/.*.test.js$',
  transform: {
    '\\.js$': ['babel-jest'],
    '\\.graphql$': 'jest-transform-graphql',
  },
  reporters: ['default', ['jest-junit', { outputDirectory: './test-results/jest/', outputName: 'results.xml' }]],
  collectCoverageFrom: ['src/**/*.js'],
  coveragePathIgnorePatterns: ['/node_modules/'],
  testPathIgnorePatterns: ['/node_modules/'],
};
