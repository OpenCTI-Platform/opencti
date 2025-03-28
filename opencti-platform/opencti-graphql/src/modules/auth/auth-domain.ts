import ejs from 'ejs';
import { getUserByEmail } from '../../domain/user';
import { UnsupportedError } from '../../config/errors';
import { sendMail } from '../../database/smtp';
import type { AuthContext } from '../../types/user';
import type { AskSendOtpInput, User } from '../../generated/graphql';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { ADMIN_USER } from '../../../tests/utils/testQuery';
import { OCTI_EMAIL_TEMPLATE } from '../../utils/emailTemplates/octiEmailTemplate';
import { redisSetForgotPasswordOtp } from '../../database/redis';

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
    const { user_email, name } = await getUser(input.email);
    const email = user_email.toLowerCase();
    await redisSetForgotPasswordOtp(email, resetOtp);
    const body = `Hi ${
      name
    },</br>`
      + 'A request has been made to reset your OpenCTI password.</br>'
      + `Enter the following password recovery code: ${
        resetOtp}`;

    const sendMailArgs: SendMailArgs = {
      from: settings.platform_email,
      to: user_email,
      subject: `${resetOtp} is your recovery code of your OpenCTI account`,
      html: ejs.render(OCTI_EMAIL_TEMPLATE, { settings, body }),
    };
    await sendMail(sendMailArgs);
  } catch (e) {
    // Prevent wrong email address, but return true too if it fails
    // logApp.error('Error occurred while sending password reset email:', { cause: e });
    console.error('Error occurred while sending password reset email:', e);
  }
  return true;
};
