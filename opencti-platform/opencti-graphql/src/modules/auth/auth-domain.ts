import ejs from 'ejs';
import { authenticator } from 'otplib';
import { findById, getUserByEmail, userEditField } from '../../domain/user';
import { AuthenticationFailure, UnsupportedError } from '../../config/errors';
import { sendMail } from '../../database/smtp';
import type { AuthContext } from '../../types/user';
import type { AskSendOtpInput, Verify2faInput, User, VerifyOtpInput, ChangePasswordInput } from '../../generated/graphql';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { ADMIN_USER } from '../../../tests/utils/testQuery';
import { OCTI_EMAIL_TEMPLATE } from '../../utils/emailTemplates/octiEmailTemplate';
import { OTP_TTL, redisGetForgotPasswordOtp, redisSetForgotPasswordOtp } from '../../database/redis';
import { publishUserAction } from '../../listener/UserActionListener';
import { SYSTEM_USER } from '../../utils/access';
import { killUserSessions } from '../../database/session';

export const getUser = async (email: string): Promise<User> => {
  const user: any = await getUserByEmail(email);
  if (user.external) throw UnsupportedError('External user');
  return user;
};

export const generateOtp = () => {
  let otp = '';
  for (let i = 0; i < 8; i += 1) {
    const random = Math.floor(Math.random() * 10);
    otp += random;
  }
  return otp;
};

interface SendMailArgs {
  from: string;
  to: string;
  subject: string;
  html: string;
}

export const askSendOtp = async (context: AuthContext, input: AskSendOtpInput) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, ADMIN_USER, ENTITY_TYPE_SETTINGS);
  const resetOtp = generateOtp();
  try {
    const user = await getUser(input.email);
    const { user_email, name } = user;
    const email = user_email.toLowerCase();
    const storedOtp = await redisGetForgotPasswordOtp(input.email);
    const isTooRecentStoredOtp = storedOtp && storedOtp.ttl > (OTP_TTL - 30);
    if (isTooRecentStoredOtp) return true;
    await redisSetForgotPasswordOtp(email, resetOtp);
    const body = `Hi ${name},</br>`
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
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `send an OTP to ${user_email}`,
    });
  } catch (e) {
    // Prevent wrong email address, but return true too if it fails
    // logApp.error('Error occurred while sending password reset email:', { cause: e });
  }
  return true;
};

export const verifyOtp = async (input: VerifyOtpInput) => {
  const storedOtp = await redisGetForgotPasswordOtp(input.email);
  const { otp_activated } = await getUser(input.email);
  if (!storedOtp.otp) {
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `OTP checked is expired or not found for ${input.email}`,
    });
    throw UnsupportedError('OTP expired or not found. Please request a new one.');
  }
  if (storedOtp.otp !== input.otp) {
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'authentication',
      event_scope: 'forgot',
      event_access: 'administration',
      context_data: undefined,
      message: `OTP checked is invalid for ${input.email}`,
    });
    throw UnsupportedError('Invalid OTP. Please check the code and try again.');
  }
  await publishUserAction({
    user: SYSTEM_USER,
    event_type: 'authentication',
    event_scope: 'forgot',
    event_access: 'administration',
    context_data: undefined,
    message: `OTP checked is valid for ${input.email}`,
  });
  return { otp_activated: otp_activated || false };
};

export const verify2fa = async (input: Verify2faInput) => {
  const user = await getUser(input.email);
  if (!user.otp_activated || !user.otp_secret) {
    throw AuthenticationFailure();
  }
  const isValidated = authenticator.check(input.code, user.otp_secret);
  if (!isValidated) {
    throw AuthenticationFailure();
  }
  return isValidated;
};

export const changePassword = async (context: AuthContext, input: ChangePasswordInput) => {
  try {
    const user = await getUser(input.email);
    const authUser = await findById(context, ADMIN_USER, user.id);
    await userEditField(context, authUser, authUser.id, [
      { key: 'password', value: [input.newPassword] }
    ]);
    await killUserSessions(authUser.id);
    return true;
  } catch (error) {
    throw UnsupportedError('Password change failed, please try again.');
  }
};
