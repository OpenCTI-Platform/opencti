import { createGuardrails, OTP } from 'otplib';

const guardrails = createGuardrails({
  MIN_SECRET_BYTES: 10, // needed to support MFA code generated with otplib v12
});

class GuardedOTP extends OTP {
  // since OTP constructor can't support guardrails option for now, override the verify method accordingly
  verify(options: Parameters<OTP['verify']>[0]) {
    return super.verify({
      ...options,
      guardrails,
    });
  }
}

const totp = new GuardedOTP(); // defaults to TOTP strategy

export { totp };
