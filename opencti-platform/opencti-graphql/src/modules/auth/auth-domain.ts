import { getUserByEmail } from '../../domain/user';
import { UnsupportedError } from '../../config/errors';
import ejs from 'ejs';
import { BASIC_EMAIL_TEMPLATE } from '../../utils/emailTemplates/basicEmailTemplate';
import { sendMail } from '../../database/smtp';

export const getEmail = async (email: string) => {
  // @ts-ignore
  const user = await getUserByEmail(email);
  // @ts-ignore
  if (user.external) throw UnsupportedError('External user');
  // @ts-ignore
  return user.user_email;
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
  const emailChecked = await getEmail(email);
  const resetToken = generateCode();
  const username = emailChecked; // TODO : get the username
  const emailSubject = resetToken + ' is your recovery code of your OpenCTI account';
  const body = 'Hi '
    + username
    + ',</br>'
    + 'A request has been made to reset your OpenBAS password.</br>'
    + 'Enter the following password recovery code: '
    + resetToken;
  const emailBody = ejs.render(BASIC_EMAIL_TEMPLATE, { body: body });

  const sendMailArgs: SendMailArgs = {
    from: 'admin@opencti.io', // TODO : get the platform email
    to: emailChecked,
    subject: emailSubject,
    html: emailBody,
  };
  await sendMail(sendMailArgs);

  return true;
};