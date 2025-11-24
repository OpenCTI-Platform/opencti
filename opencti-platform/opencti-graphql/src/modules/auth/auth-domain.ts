import ejs from 'ejs';
import { authenticator } from 'otplib';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import { findById, getUserByEmail, userEditField } from '../../domain/user';
import { AuthenticationFailure, UnsupportedError } from '../../config/errors';
import { sendMail } from '../../database/smtp';
import type { AuthContext } from '../../types/user';
import type { AskSendOtpInput, ChangePasswordInput, VerifyMfaInput, VerifyOtpInput } from '../../generated/graphql';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { OCTI_EMAIL_TEMPLATE } from '../../utils/emailTemplates/octiEmailTemplate';
import { OTP_TTL, redisDelForgotPassword, redisGetForgotPasswordOtp, redisGetForgotPasswordOtpPointer, redisSetForgotPasswordOtp } from '../../database/redis';
import { publishUserAction } from '../../listener/UserActionListener';
import { SYSTEM_USER } from '../../utils/access';
import { killUserSessions } from '../../database/session';
import { logApp } from '../../config/conf';
import type { SendMailArgs } from '../../types/smtp';
import { addForgotPasswordCount } from '../../manager/telemetryManager';

export const getLocalProviderUser = async (email: string) => {
  const user: any = await getUserByEmail(email);
  return user;
};

export const generateOtp = () => {
  const array = new Uint8Array(8);
  crypto.getRandomValues(array);
  return Array.from(array, (n) => (n % 10).toString()).join('');
};

export const askSendOtp = async (context: AuthContext, input: AskSendOtpInput) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const resetOtp = generateOtp();
  const hashedOtp = bcrypt.hashSync(resetOtp);
  const transactionId = uuid();

  // Get user, and block if no user found or user is external
  const user: any = await getUserByEmail(input.email);
  if (!user || user.external) {
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `Invalid email ${input.email} provided for password reset`,
    });
    return transactionId;
  }
  const { user_email, name, otp_activated: mfa_activated, id } = user;
  const email = user_email.toLowerCase();

  // Don't generate new redis key under 30-second delay
  const previousKey = await redisGetForgotPasswordOtpPointer(input.email);
  const isTooRecent = previousKey.ttl > (OTP_TTL - 30);
  if (isTooRecent) return transactionId;

  // Delete the previous OTP if it exists based on the pointer
  if (previousKey.id) await redisDelForgotPassword(previousKey.id, email);

  // Store the new OTP; create a new key using the new UUID
  await redisSetForgotPasswordOtp(transactionId, { hashedOtp, email, mfa_activated: mfa_activated ?? false, mfa_validated: false, userId: id });

  // Send email
  try {
    const body = `<p>Hi ${name},</p>`
      + '<p>We have received a request to reset the password for your account associated with this email address. To proceed with resetting your password, please use the verification code provided below:</p>'
      + `<p><b>${resetOtp}</b></p>`
      + '<p>Please enter this code on the password reset page to create a new password for your account.</p>'
      + '<p>If you did not request this password reset, it is possible that someone else is trying to access your account. Do not forward or give this code to anyone.</p>'
      + '<p>For any assistance or if you have concerns, do not hesitate to contact the system administrator.</p>'
      + '<p>Sincerely,</p>';
    const sendMailArgs: SendMailArgs = {
      from: `${settings.platform_title} <${settings.platform_email}>`,
      to: user_email,
      subject: 'Your OpenCTI account - Password recovery code',
      html: ejs.render(OCTI_EMAIL_TEMPLATE, { settings, body }),
    };
    await sendMail(sendMailArgs, { identifier: id, category: 'password-reset' });
    // Audit log for sending the OTP
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `sends password reset code to ${user_email}`,
    });
  } catch (e) {
    logApp.error('Error occurred while sending password reset email:', { cause: e });
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `Failed to send password reset code to ${input.email}`,
    });
  }
  await addForgotPasswordCount();

  // In all cases, return the transaction ID
  return transactionId;
};

export const verifyOtp = async (input: VerifyOtpInput) => {
  const { hashedOtp, email, mfa_activated } = await redisGetForgotPasswordOtp(input.transactionId);
  if (!hashedOtp) {
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `Password reset code is expired or not found for ${input.transactionId}`,
    });
    throw UnsupportedError('Password reset code expired or not found. Please request a new one.');
  }
  const isMatch = bcrypt.compareSync(input.otp, hashedOtp);
  if (!isMatch) {
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `Password reset code is invalid for ${email}`,
    });
    throw UnsupportedError('Invalid password reset code. Please check the code and try again.');
  }
  await publishUserAction({
    user: SYSTEM_USER,
    event_type: 'authentication',
    event_scope: 'forgot',
    event_access: 'administration',
    context_data: undefined,
    message: `Password reset code is valid for ${email}`,
  });
  return { mfa_activated };
};

export const verifyMfa = async (context: AuthContext, input: VerifyMfaInput) => {
  const { hashedOtp, email, mfa_activated, ttl, userId } = await redisGetForgotPasswordOtp(input.transactionId);
  const { otp_secret: mfa_secret } = await findById(context, SYSTEM_USER, userId);
  if (!mfa_activated || !mfa_secret) {
    throw AuthenticationFailure();
  }
  const isValidated = authenticator.check(input.code, mfa_secret);
  if (!isValidated) {
    throw AuthenticationFailure();
  } else {
    await redisSetForgotPasswordOtp(input.transactionId, { hashedOtp, email, mfa_activated, mfa_validated: isValidated, userId }, ttl);
  }
  return isValidated;
};

export const changePassword = async (context: AuthContext, input: ChangePasswordInput) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const { hashedOtp, email, mfa_activated, mfa_validated, userId } = await redisGetForgotPasswordOtp(input.transactionId);
  const isMatch = bcrypt.compareSync(input.otp, hashedOtp);
  const isStateMfaValid = !mfa_activated || (mfa_activated && mfa_validated);
  if (!isMatch || !isStateMfaValid) {
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `Password reset code is invalid for ${email}`,
    });
    throw UnsupportedError('Invalid password reset code. Please check the code and try again.');
  }
  try {
    const authUser = await findById(context, SYSTEM_USER, userId);
    await userEditField(context, SYSTEM_USER, authUser.id, [
      { key: 'password', value: [input.newPassword] }
    ]);
    await killUserSessions(authUser.id);
    await redisDelForgotPassword(input.transactionId, email);
    const body = `<p>Hi ${authUser.name},</p>`
      + '<p>We wanted to let you know that your account password was successfully changed.</p>'
      + '<p>If you initiated this change, no further action is required. However, if you did not request this change, please reset your password immediately and contact the system administrator.</p>'
      + '<p>Sincerely,</p>';
    const sendMailArgs: SendMailArgs = {
      from: `${settings.platform_title} <${settings.platform_email}>`,
      to: email,
      subject: 'Your OpenCTI account - Password updated',
      html: ejs.render(OCTI_EMAIL_TEMPLATE, { settings, body }),
    };
    await sendMail(sendMailArgs, { identifier: userId, category: 'password-change' });
    return true;
  } catch (_error) {
    throw UnsupportedError('Password change failed, please try again.');
  }
};
