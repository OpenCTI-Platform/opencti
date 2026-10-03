import { describe, expect, it } from 'vitest';
import { normalizeFrontendError } from '../normalizeFrontendError';

describe('normalizeFrontendError', () => {
  it('should keep a real Error message unchanged', () => {
    const error = new TypeError('Failed to fetch');
    const { message, stack } = normalizeFrontendError(error);
    expect(message).toEqual('TypeError: Failed to fetch');
    expect(stack).toEqual(error.stack);
  });

  it('should fall back to a readable message when the Error has no message', () => {
    const { message } = normalizeFrontendError(new Error());
    expect(message).toEqual('Error (no message provided)');
  });

  it('should wrap a thrown string into a readable Error message', () => {
    const { message, stack } = normalizeFrontendError('something went wrong');
    expect(message).toEqual('Error: something went wrong');
    expect(stack).toBeDefined();
  });

  it('should surface only key names, never values, for a thrown plain object', () => {
    const { message } = normalizeFrontendError({ reason: 'network down', token: 'super-secret' });
    expect(message).toEqual('Error: Non-Error object thrown with keys: [reason, token]');
    expect(message).not.toContain('network down');
    expect(message).not.toContain('super-secret');
  });

  it('should not throw and should still produce a message when the thrown value is a circular reference', () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;

    expect(() => normalizeFrontendError(circular)).not.toThrow();
    const { message } = normalizeFrontendError(circular);
    expect(message).toEqual('Error: Non-Error object thrown with keys: [self]');
  });

  it('should not throw and should still produce a message when the thrown value is undefined', () => {
    expect(() => normalizeFrontendError(undefined)).not.toThrow();
    const { message } = normalizeFrontendError(undefined);
    expect(message).toEqual('Error: undefined');
  });

  it('should not throw when the Error message conversion itself throws', () => {
    const hostileError = new Error('boom');
    hostileError.toString = () => {
      throw new Error('nested failure');
    };

    expect(() => normalizeFrontendError(hostileError)).not.toThrow();
    const { message } = normalizeFrontendError(hostileError);
    expect(message).toEqual('Error: <unreadable error message>');
  });
});
