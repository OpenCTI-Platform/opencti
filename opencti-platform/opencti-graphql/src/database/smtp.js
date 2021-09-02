import nodemailer from 'nodemailer';
import conf, { booleanConf } from '../config/conf';
import { DatabaseError } from '../config/errors';

const USE_SSL = booleanConf('smtp:use_ssl', false);

const smtpOptions = {
  host: conf.get('smtp:hostname'),
  port: conf.get('smtp:port'),
  secure: USE_SSL,
  tls: {
    rejectUnauthorized: conf.get('smtp:rejectUnauthorized'),
  },
};

if (conf.get('smtp:username') && conf.get('smtp:username').length > 0) {
  smtpOptions.auth = {
    user: conf.get('smtp:username'),
    pass: conf.get('smtp:password'),
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
  const { to, subject, html } = args;
  await transporter.sendMail({
    from: conf.get('smtp:from_email'),
    to,
    subject,
    html,
  });
};
