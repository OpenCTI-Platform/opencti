import { describe, expect, it } from 'vitest';
import { isLockError } from '../../../src/database/sequencer/sequencer-multi-writer';

// pycti parity (task 0040): the worker-less intake runs again an operation refused because its
// entities are locked, as pycti does; the refusal must be recognized whatever form it reached the
// intake in.
describe('lock errors', () => {
  it('should recognize a lock refused by redlock, by a lock site, or wrapped by GraphQL', () => {
    expect(isLockError({ name: 'ExecutionError', message: 'The operation was unable to achieve a quorum during its retry window.' })).toBe(true);
    expect(isLockError({ message: 'Execution timeout, too many concurrent call on the same entities', extensions: { code: 'LOCK_ERROR' } })).toBe(true);
    expect(isLockError({ message: 'refused', extensions: { code: 'LOCK_ERROR' } })).toBe(true);
    expect(isLockError(new Error('Unexpected error value: { message: "Execution timeout, too many concurrent call on the same entities", extensions: { code: "LOCK_ERROR", data: [Object] } }'))).toBe(true);
    expect(isLockError({ message: 'Element not found', extensions: { code: 'MISSING_REFERENCE_ERROR' } })).toBe(false);
    expect(isLockError(new Error('connect ECONNREFUSED'))).toBe(false);
    expect(isLockError(undefined)).toBe(false);
  });
});
