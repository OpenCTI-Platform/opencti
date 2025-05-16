import ejs from 'ejs';
import { authenticator } from 'otplib';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import { findById, getUserByEmail, userEditField } from '../../domain/user';
import { AuthenticationFailure, UnsupportedError } from '../../config/errors';
import { sendMail } from '../../database/smtp';
import type { AuthContext, AuthUser } from '../../types/user';
import type { AskSendOtpInput, ChangePasswordInput, VerifyMfaInput, VerifyOtpInput } from '../../generated/graphql';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { ADMIN_USER } from '../../../tests/utils/testQuery';
import { OCTI_EMAIL_TEMPLATE } from '../../utils/emailTemplates/octiEmailTemplate';
import { OTP_TTL, redisDelForgotPassword, redisGetForgotPasswordOtp, redisGetForgotPasswordOtpPointer, redisSetForgotPasswordOtp } from '../../database/redis';
import { publishUserAction } from '../../listener/UserActionListener';
import { SYSTEM_USER } from '../../utils/access';
import { killUserSessions } from '../../database/session';
import { logApp } from '../../config/conf';
import type { SendMailArgs } from '../../types/smtp';

export const getLocalProviderUser = async (email: string): Promise<AuthUser> => {
  const user: any = await getUserByEmail(email);
  if (!user) throw UnsupportedError('User not found');
  if (user.external) throw UnsupportedError('External user');
  return user;
};

export const generateOtp = () => {
  const array = new Uint8Array(8);
  crypto.getRandomValues(array);
  return Array.from(array, (n) => (n % 10).toString()).join('');
};

export const askSendOtp = async (context: AuthContext, input: AskSendOtpInput) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, ADMIN_USER, ENTITY_TYPE_SETTINGS);
  const resetOtp = generateOtp();
  const transactionId = uuid();
  try {
    // Retrieve user information
    const user = await getLocalProviderUser(input.email);
    const {
      user_email,
      name,
      otp_activated: mfa_activated,
      id
    } = user;
    const email = user_email.toLowerCase();
    // Check the 30-second delay key
    const storedOtp = await redisGetForgotPasswordOtpPointer(input.email);
    const isTooRecentStoredOtp = storedOtp.ttl > (OTP_TTL - 30);
    if (isTooRecentStoredOtp) return transactionId;
    // Delete the previous OTP if it exists based on the pointer
    const previousPointer = await redisGetForgotPasswordOtpPointer(email);
    if (previousPointer.id) {
      await redisDelForgotPassword(previousPointer.id, email);
    }
    // Generate and store the new OTP; create a new pointer using the new UUID
    const hashedOtp = bcrypt.hashSync(resetOtp);
    await redisSetForgotPasswordOtp(transactionId, { hashedOtp, email, mfa_activated: mfa_activated ?? false, mfa_validated: false, userId: id });
    // Create and send the email
    const body = `Hi ${name},</br></br>`
        + 'A request has been made to reset your OpenCTI password.</br></br>'
        + 'Enter the following password recovery code:</br></br>'
        + `<b>${resetOtp}</b>`;
    const sendMailArgs: SendMailArgs = {
      from: settings.platform_email,
      to: user_email,
      subject: `${resetOtp} is your recovery code of your OpenCTI account`,
      html: ejs.render(OCTI_EMAIL_TEMPLATE, { settings, body }),
    };
    await sendMail(sendMailArgs);
    // Audit log for sending the OTP
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `send an OTP to ${user_email}`,
    });
  } catch (e) {
    // Prevent wrong email address, but return transactionId too if it fails
    logApp.error('Error occurred while sending password reset email:', { cause: e });
    // Audit log in case of error during OTP sending
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `failed to send OTP to ${input.email}`,
    });
  }
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
      message: `OTP checked is expired or not found for ${input.transactionId}`,
    });
    throw UnsupportedError('OTP expired or not found. Please request a new one.');
  }
  const isMatch = bcrypt.compareSync(input.otp, hashedOtp);
  if (!isMatch) {
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `OTP checked is invalid for ${email}`,
    });
    throw UnsupportedError('Invalid OTP. Please check the code and try again.');
  }
  await publishUserAction({
    user: SYSTEM_USER,
    event_type: 'authentication',
    event_scope: 'forgot',
    event_access: 'administration',
    context_data: undefined,
    message: `OTP checked is valid for ${email}`,
  });
  return { mfa_activated };
};

export const verifyMfa = async (context: AuthContext, input: VerifyMfaInput) => {
  const { hashedOtp, email, mfa_activated, ttl, userId } = await redisGetForgotPasswordOtp(input.transactionId);
  const { otp_secret: mfa_secret } = await findById(context, ADMIN_USER, userId);
  if (!mfa_activated || !mfa_secret) {
    throw AuthenticationFailure();
  }
  const isValidated = authenticator.check(input.mfaOtp, mfa_secret);
  if (!isValidated) {
    throw AuthenticationFailure();
  } else {
    await redisSetForgotPasswordOtp(input.transactionId, { hashedOtp, email, mfa_activated, mfa_validated: isValidated, userId }, ttl);
  }
  return isValidated;
};

export const changePassword = async (context: AuthContext, input: ChangePasswordInput) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, ADMIN_USER, ENTITY_TYPE_SETTINGS);
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
      message: `OTP checked is invalid for ${email}`,
    });
    throw UnsupportedError('Invalid OTP. Please check the code and try again.');
  }
  try {
    const authUser = await findById(context, ADMIN_USER, userId);
    await userEditField(context, authUser, authUser.id, [
      { key: 'password', value: [input.newPassword] }
    ]);
    await killUserSessions(authUser.id);
    await redisDelForgotPassword(input.transactionId, email);
    const body = `Hi ${authUser.name},</br></br>`
      + 'We wanted to let you know that your account password was successfully changed.</br></br>'
      + 'If you initiated this change, no further action is required. However, if you did not authorize this change, please reset your password immediately and contact the system administrator so that we may investigate and take appropriate measures to secure your account.</br></br>'
      + 'Sincerely,</br></br>'
      + 'Filigran</br></br>';
    const sendMailArgs: SendMailArgs = {
      from: settings.platform_email,
      to: email,
      subject: 'The password of your OpenCTI account has been changed',
      html: ejs.render(OCTI_EMAIL_TEMPLATE, { settings, body }),
    };
    await sendMail(sendMailArgs);
    return true;
  } catch (error) {
    throw UnsupportedError('Password change failed, please try again.');
  }
};
