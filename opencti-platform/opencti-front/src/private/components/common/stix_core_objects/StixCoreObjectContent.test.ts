import { describe, expect, it } from 'vitest';
import { isPdfPasswordError } from './StixCoreObjectContentPdfUtils';

describe('isPdfPasswordError', () => {
  it('returns true when error name indicates password issue', () => {
    expect(isPdfPasswordError({ name: 'PasswordException' })).toBe(true);
  });

  it('returns true when error message indicates missing password', () => {
    expect(isPdfPasswordError({ message: 'No password given' })).toBe(true);
  });

  it('returns false for non-password errors', () => {
    expect(isPdfPasswordError({ name: 'AbortException', message: 'The operation was aborted.' })).toBe(false);
  });
});
