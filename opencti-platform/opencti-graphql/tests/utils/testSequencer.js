// eslint-disable-next-line import/no-extraneous-dependencies
const TestSequencer = require('@jest/test-sequencer').default;

class CustomSequencer extends TestSequencer {
  // eslint-disable-next-line class-methods-use-this
  sort(tests) {
    // Test structure information
    // https://github.com/facebook/jest/blob/6b8b1404a1d9254e7d5d90a8934087a9c9899dab/packages/jest-runner/src/types.ts#L17-L21
    const copyTests = Array.from(tests);
    return copyTests.sort((testA, testB) => (testA.path > testB.path ? 1 : -1));
  }
}

module.exports = CustomSequencer;
