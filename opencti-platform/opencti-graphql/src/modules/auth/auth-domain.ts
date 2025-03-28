import ejs from 'ejs';
import { getUserByEmail } from '../../domain/user';
import { UnsupportedError } from '../../config/errors';
import { sendMail } from '../../database/smtp';
import type { AuthContext } from '../../types/user';
import type { User } from '../../generated/graphql';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { ADMIN_USER } from '../../../tests/utils/testQuery';
import { OCTI_EMAIL_TEMPLATE } from '../../utils/emailTemplates/octiEmailTemplate';

export const getUser = async (email: string): Promise<User> => {
  const user: any = await getUserByEmail(email);
  if (user.external) throw UnsupportedError('External user');
  return user;
};

export const generateCode = () => {
  let code = '';
  for (let i = 0; i < 8; i += 1) {
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

export const askSendToken = async (context: AuthContext, email: string) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, ADMIN_USER, ENTITY_TYPE_SETTINGS);
  const resetToken = generateCode();
  try {
    const { user_email, name } = await getUser(email);
    const body = `Hi ${
      name
    },</br>`
      + 'A request has been made to reset your OpenCTI password.</br>'
      + `Enter the following password recovery code: ${
        resetToken}`;

    const sendMailArgs: SendMailArgs = {
      from: settings.platform_email,
      to: user_email,
      subject: `${resetToken} is your recovery code of your OpenCTI account`,
      html: ejs.render(OCTI_EMAIL_TEMPLATE, { body }),
    };
    await sendMail(sendMailArgs);
  } catch (e) {
    // Prevent wrong email address, but return true too if it fail
    // TODO : log ?
    // logApp.error('Error occurred while sending password reset email:', { cause: e });
  }
  return true;
};
