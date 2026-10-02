import { describe, expect, it } from 'vitest';
import { PASSWORD_CHANGE_THROTTLED, PASSWORD_RESET_EXPIRED, PASSWORD_REUSED, passwordChangeErrorCode, passwordChangeErrorMessages } from './passwordChangeErrors';

const relayError = (errors: unknown[]) => ({ res: { errors } });

describe('passwordChangeErrorCode', () => {
  it('reads the code from the error extensions', () => {
    expect(passwordChangeErrorCode(relayError([{ message: 'x', extensions: { code: PASSWORD_REUSED } }]))).toBe(PASSWORD_REUSED);
  });

  it('falls back to the error name the server copies the code into', () => {
    expect(passwordChangeErrorCode(relayError([{ message: 'x', name: PASSWORD_CHANGE_THROTTLED }]))).toBe(PASSWORD_CHANGE_THROTTLED);
  });

  it('finds the code among several errors', () => {
    const error = relayError([{ message: 'a', extensions: { code: 'FUNCTIONAL_ERROR' } }, { message: 'b', extensions: { code: PASSWORD_REUSED } }]);
    expect(passwordChangeErrorCode(error)).toBe(PASSWORD_REUSED);
  });

  it('returns nothing for the other refusals, which keep their own handling', () => {
    expect(passwordChangeErrorCode(relayError([{ message: 'x', extensions: { code: 'FUNCTIONAL_ERROR' } }]))).toBeUndefined();
    expect(passwordChangeErrorCode(relayError([]))).toBeUndefined();
    expect(passwordChangeErrorCode(new Error('network'))).toBeUndefined();
    expect(passwordChangeErrorCode(undefined)).toBeUndefined();
  });
});

describe('passwordChangeErrorMessages', () => {
  it('translates a message for each code', () => {
    const messages = passwordChangeErrorMessages((message) => `t:${message}`);
    expect(messages[PASSWORD_REUSED]).toBe('t:This password has already been used recently. Please choose a different one.');
    expect(messages[PASSWORD_CHANGE_THROTTLED]).toBe('t:Too many password change attempts. Please try again in a few minutes.');
    expect(messages[PASSWORD_RESET_EXPIRED]).toBe('t:Password reset code expired or not found. Please request a new one.');
  });

  it('recognises the expired reset code', () => {
    expect(passwordChangeErrorCode(relayError([{ message: 'x', extensions: { code: PASSWORD_RESET_EXPIRED } }]))).toBe(PASSWORD_RESET_EXPIRED);
  });
});
