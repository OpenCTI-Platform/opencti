import bcrypt from 'bcryptjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { changePassword, verifyMfa, verifyOtp } from '../../../../src/modules/auth/auth-domain';
import { redisGetForgotPasswordOtp } from '../../../../src/database/redis';
import { findById, userEditField } from '../../../../src/modules/user/user-domain';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/redis', () => ({
  OTP_TTL: 600,
  redisGetForgotPasswordOtp: vi.fn(),
  redisGetForgotPasswordOtpPointer: vi.fn(),
  redisSetForgotPasswordOtp: vi.fn(),
  redisDelForgotPassword: vi.fn(),
}));

vi.mock('../../../../src/modules/user/user-domain', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    findById: vi.fn(),
    getUserByEmail: vi.fn(),
    userEditField: vi.fn(),
  };
});

vi.mock('../../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(async () => ({})),
}));

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

describe('forgot password with an unknown transaction', () => {
  const prototype = Object.prototype as Record<string, unknown>;
  const INHERITED_OTP = '12345678';

  beforeEach(() => {
    vi.mocked(redisGetForgotPasswordOtp).mockResolvedValue(null);
    prototype.hashedOtp = bcrypt.hashSync(INHERITED_OTP, 4);
    prototype.userId = 'inherited-user-id';
    prototype.email = 'inherited@test.com';
    prototype.mfa_activated = true;
    prototype.mfa_validated = true;
  });

  afterEach(() => {
    delete prototype.hashedOtp;
    delete prototype.userId;
    delete prototype.email;
    delete prototype.mfa_activated;
    delete prototype.mfa_validated;
  });

  it('should refuse to verify the code', async () => {
    await expect(verifyOtp({ transactionId: 'unknown', otp: INHERITED_OTP }))
      .rejects.toThrow('Password reset code expired or not found. Please request a new one.');
  });

  it('should refuse to verify the MFA code', async () => {
    await expect(verifyMfa(testContext, { transactionId: 'unknown', code: '000000' }))
      .rejects.toThrow('Bad login or password');
    expect(findById).not.toHaveBeenCalled();
  });

  it('should refuse to change the password', async () => {
    await expect(changePassword(testContext, { transactionId: 'unknown', otp: INHERITED_OTP, newPassword: 'new-password' }))
      .rejects.toThrow('Invalid password reset code. Please check the code and try again.');
    expect(userEditField).not.toHaveBeenCalled();
  });
});
