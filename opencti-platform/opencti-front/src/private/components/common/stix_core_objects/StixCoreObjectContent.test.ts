import { describe, expect, it } from 'vitest';
import { isOngoingExport, isPdfPasswordError } from './StixCoreObjectContentPdfUtils';

describe('isOngoingExport', () => {
  it('returns true for an export work waiting for its connector', () => {
    expect(isOngoingExport({ uploadStatus: 'wait' })).toBe(true);
  });

  it('returns true for an export work in progress', () => {
    expect(isOngoingExport({ uploadStatus: 'progress' })).toBe(true);
  });

  it('returns false for a pushed file or a finished work', () => {
    expect(isOngoingExport({ uploadStatus: 'complete' })).toBe(false);
    expect(isOngoingExport({ uploadStatus: 'timeout' })).toBe(false);
    expect(isOngoingExport(undefined)).toBe(false);
  });
});

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
