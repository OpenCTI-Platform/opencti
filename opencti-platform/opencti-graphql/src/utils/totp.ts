import { createGuardrails, OTP } from 'otplib';

const totp = new OTP({
  guardrails: createGuardrails({
    MIN_SECRET_BYTES: 10, // needed to support MFA code generated with otplib v12
  }),
}); // defaults to TOTP strategy

export { totp };
