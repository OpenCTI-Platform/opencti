module.exports = {
  testEnvironment: 'node',
  testRegex: 'tests/.*-test.js$',
  transform: {
    '\\.js$': ['babel-jest', { plugins: ['require-context-hook'] }],
    '\\.graphql$': 'jest-transform-graphql'
  },
  reporters: ['default', ['jest-junit', { outputDirectory: './test-results/jest/', outputName: 'results.xml' }]],
  collectCoverageFrom: ['src/**/*.js']
};
