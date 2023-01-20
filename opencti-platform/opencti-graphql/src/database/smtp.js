import nodemailer from 'nodemailer';
import conf, { booleanConf } from '../config/conf';
import { DatabaseError } from '../config/errors';

const USE_SSL = booleanConf('smtp:use_ssl', false);
const REJECT_UNAUTHORIZED = booleanConf('smtp:reject_unauthorized', false);

const smtpOptions = {
  host: conf.get('smtp:hostname') || 'localhost',
  port: conf.get('smtp:port') || 25,
  secure: USE_SSL,
  tls: {
    rejectUnauthorized: REJECT_UNAUTHORIZED,
  },
};

if (conf.get('smtp:username') && conf.get('smtp:username').length > 0) {
  smtpOptions.auth = {
    user: conf.get('smtp:username'),
    pass: conf.get('smtp:password') || '',
  };
}

export const transporter = nodemailer.createTransport(smtpOptions);

export const smtpIsAlive = async () => {
  try {
    await transporter.verify();
  } catch {
    throw DatabaseError('SMTP seems down, disable the subscription manager if you dont want it');
  }
  return true;
};

export const sendMail = async (args) => {
  const { from, to, subject, html } = args;
  await transporter.sendMail({ from, to, subject, html });
};
