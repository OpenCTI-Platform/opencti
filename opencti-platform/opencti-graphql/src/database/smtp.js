import nodemailer from 'nodemailer';
import conf, { booleanConf, logApp } from '../config/conf';

const USE_SSL = booleanConf('smtp:use_ssl', false);
const REJECT_UNAUTHORIZED = booleanConf('smtp:reject_unauthorized', false);
const SMTP_ENABLE = booleanConf('smtp:enabled', true);

const smtpOptions = {
  host: conf.get('smtp:hostname') || 'localhost',
  port: conf.get('smtp:port') || 25,
  secure: USE_SSL,
  tls: {
    rejectUnauthorized: REJECT_UNAUTHORIZED,
    maxVersion: conf.get('smtp:tls_max_version'),
    minVersion: conf.get('smtp:tls_min_version'),
    ciphers: conf.get('smtp:tls_ciphers'),
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
  if (SMTP_ENABLE) {
    try {
      await transporter.verify();
    } catch {
      logApp.warn('SMTP seems down, email notification may not work');
    }
  }
  return true;
};

export const sendMail = async (args) => {
  if (SMTP_ENABLE) {
    const { from, to, bcc, subject, html, attachments } = args;
    await transporter.sendMail({ from, to, bcc, subject, html, attachments });
  }
};
