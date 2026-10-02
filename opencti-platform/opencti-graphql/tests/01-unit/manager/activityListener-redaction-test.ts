import { describe, expect, it } from 'vitest';
import { cleanInputData } from '../../../src/manager/activityListener';
import { REDACTED_INFORMATION } from '../../../src/database/utils';

describe('activityListener cleanInputData - credentials in audit data', () => {
  it('redacts a password sent as a single edit input', () => {
    const data = cleanInputData({ operation: 'TestOperation', input: { id: 'user-1', input: { key: 'password', value: 'Clear-text-1!' } } });
    expect(data.input.input).toEqual({ key: 'password', value: REDACTED_INFORMATION });
  });

  it('still redacts a password sent in an array of edit inputs', () => {
    const data = cleanInputData({ input: [{ key: 'password', value: ['Clear-text-1!'] }, { key: 'language', value: ['fr-fr'] }] });
    expect(data.input).toEqual([{ password: REDACTED_INFORMATION }, { key: 'language', value: ['fr-fr'] }]);
  });

  it('redacts the reset code and the new password of a forgot-password change', () => {
    const data = cleanInputData({ input: { input: { transactionId: 'tx-1', otp: '12345678', newPassword: 'Clear-text-1!' } } });
    expect(data.input.input).toEqual({ transactionId: 'tx-1', otp: REDACTED_INFORMATION, newPassword: REDACTED_INFORMATION });
  });
});
