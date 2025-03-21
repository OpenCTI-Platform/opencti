import { getUserByEmail } from '../../domain/user';
import { UnsupportedError } from '../../config/errors';
import ejs from 'ejs';
import { BASIC_EMAIL_TEMPLATE } from '../../utils/emailTemplates/basicEmailTemplate';
import { sendMail } from '../../database/smtp';
import type { AuthUser } from '../../types/user';
import type { User, UserAccount } from '../../generated/graphql';

export const getUser = async (email: string): Promise<User> => {
  const user: any = await getUserByEmail(email);
  if (user.external) throw UnsupportedError('External user');
  return user;
};

export const generateCode = () => {
  let code = '';
  for (let i = 0; i < 8; i++) {
    const random = Math.floor(Math.random() * 10);
    code += random;
  }
  return code;
};

interface SendMailArgs {
  from: string;
  to: string;
  subject: string;
  html: string;
}

export const askResetPassword = async (email: string) => {
  try {
    const { user_email, name } = await getUser(email);
    const resetToken = generateCode();
    const body = 'Hi '
      + name
      + ',</br>'
      + 'A request has been made to reset your OpenBAS password.</br>'
      + 'Enter the following password recovery code: '
      + resetToken;

    const sendMailArgs: SendMailArgs = {
      from: 'admin@opencti.io', // TODO : get the platform email
      to: user_email,
      subject: resetToken + ' is your recovery code of your OpenCTI account',
      html: ejs.render(BASIC_EMAIL_TEMPLATE, { body: body }),
    };
    await sendMail(sendMailArgs);
  } catch (e) {
    // Prevent wrong email address, but return true too if it fail
    // TODO : log ?
  }

  return true;
};