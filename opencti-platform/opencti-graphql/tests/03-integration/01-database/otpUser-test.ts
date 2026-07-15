import { afterAll, describe, expect, it } from 'vitest';
import { executionContext } from '../../../src/utils/access';
import { patchAttribute } from '../../../src/database/middleware';
import { ADMIN_USER } from '../../utils/testQuery';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { findById, otpUserActivation, otpUserDeactivation } from '../../../src/domain/user';
import { totp } from '../../../src/utils/totp';

const buildContextWithSession = (baseUser: any) => {
  const context = executionContext('otp-test') as any;
  context.req = {
    session: {
      user: { ...baseUser },
    },
  };
  return context;
};

const buildContextWithUserSession = () => {
  const context = executionContext('otp-test') as any;
  context.user_with_session = true;
  return context;
};

describe('otpUserActivation()', () => {
  afterAll(async () => {
    const context = executionContext('otp-test-cleanup') as any;
    await patchAttribute(context, ADMIN_USER, ADMIN_USER.id, ENTITY_TYPE_USER, {
      otp_activated: false,
      otp_secret: '',
      otp_qr: '',
    });
  });

  it('should activate OTP when given a valid secret/code pair', async () => {
    const cleanupContext = executionContext('otp-test-setup') as any;
    await patchAttribute(cleanupContext, ADMIN_USER, ADMIN_USER.id, ENTITY_TYPE_USER, {
      otp_activated: false,
      otp_secret: '',
      otp_qr: '',
    });
    const freshUser = await findById(cleanupContext, ADMIN_USER, ADMIN_USER.id);
    expect(freshUser.otp_activated).toBeFalsy();

    const secret = totp.generateSecret();
    // totp.generate() is async and resolves directly to the code string (no { token } wrapper).
    const code = await totp.generate({ secret });

    const context = buildContextWithSession(freshUser);
    const notifierResult = await otpUserActivation(context, freshUser, { secret, code });
    expect(notifierResult).toBeDefined();

    expect(context.req.session.user.otp_validated).toBe(true);

    const updatedUser = await findById(context, ADMIN_USER, ADMIN_USER.id);
    expect(updatedUser.otp_activated).toBe(true);
    expect(updatedUser.otp_secret).toEqual(secret);
    expect(updatedUser.otp_qr).not.toEqual('');
  });

  it('should throw AuthenticationFailure when the code is invalid', async () => {
    const cleanupContext = executionContext('otp-test-setup-invalid') as any;
    await patchAttribute(cleanupContext, ADMIN_USER, ADMIN_USER.id, ENTITY_TYPE_USER, {
      otp_activated: false,
      otp_secret: '',
      otp_qr: '',
    });
    const freshUser = await findById(cleanupContext, ADMIN_USER, ADMIN_USER.id);

    const secret = totp.generateSecret();
    const wrongCode = '000000';

    const context = buildContextWithSession(freshUser);
    await expect(otpUserActivation(context, freshUser, { secret, code: wrongCode }))
      .rejects.toThrow();

    const untouchedUser = await findById(context, ADMIN_USER, ADMIN_USER.id);
    expect(untouchedUser.otp_activated).toBeFalsy();
  });

  it('should throw UnsupportedError when OTP is already activated', async () => {
    const setupContext = executionContext('otp-test-setup-already') as any;
    await patchAttribute(setupContext, ADMIN_USER, ADMIN_USER.id, ENTITY_TYPE_USER, {
      otp_activated: false,
      otp_secret: '',
      otp_qr: '',
    });
    let freshUser = await findById(setupContext, ADMIN_USER, ADMIN_USER.id);

    const secret = totp.generateSecret();
    const code = await totp.generate({ secret });
    const activationContext = buildContextWithSession(freshUser);
    await otpUserActivation(activationContext, freshUser, { secret, code });
    freshUser = await findById(activationContext, ADMIN_USER, ADMIN_USER.id);
    expect(freshUser.otp_activated).toBe(true);

    const secondSecret = totp.generateSecret();
    const secondCode = await totp.generate({ secret: secondSecret });
    const secondContext = buildContextWithSession(freshUser);
    await expect(otpUserActivation(secondContext, freshUser, { secret: secondSecret, code: secondCode }))
      .rejects.toThrow('You need to deactivate your current 2FA before generating a new one');
  });
});

describe('otpUserDeactivation()', () => {
  it('should deactivate OTP when called with a valid user session context', async () => {
    const setupContext = executionContext('otp-test-deactivation-setup') as any;
    await patchAttribute(setupContext, ADMIN_USER, ADMIN_USER.id, ENTITY_TYPE_USER, {
      otp_activated: false,
      otp_secret: '',
      otp_qr: '',
    });
    const freshUser = await findById(setupContext, ADMIN_USER, ADMIN_USER.id);
    const secret = totp.generateSecret();
    const code = await totp.generate({ secret });
    const activationContext = buildContextWithSession(freshUser);
    await otpUserActivation(activationContext, freshUser, { secret, code });

    const activatedUser = await findById(activationContext, ADMIN_USER, ADMIN_USER.id);
    expect(activatedUser.otp_activated).toBe(true);

    const deactivationContext = buildContextWithUserSession();
    const result = await otpUserDeactivation(deactivationContext, ADMIN_USER, ADMIN_USER.id);
    expect(result).toBeDefined();

    const deactivatedUser = await findById(deactivationContext, ADMIN_USER, ADMIN_USER.id);
    expect(deactivatedUser.otp_activated).toBe(false);
    expect(deactivatedUser.otp_secret).toEqual('');
  });

  it('should throw UnsupportedError when there is no valid user session', async () => {
    const context = executionContext('otp-test-deactivation-no-session') as any;
    context.user_with_session = false;

    await expect(otpUserDeactivation(context, ADMIN_USER, ADMIN_USER.id))
      .rejects.toThrow('You need to deactivate your current 2FA in a valid user session');
  });
});
