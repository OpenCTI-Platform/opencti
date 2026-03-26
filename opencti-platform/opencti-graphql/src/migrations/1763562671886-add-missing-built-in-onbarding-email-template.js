import { executionContext, SYSTEM_USER } from '../utils/access';
import { logMigration } from '../config/conf';
import { addEmailTemplate } from '../modules/emailTemplate/emailTemplate-domain';
import { DEFAULT_EMAIL_TEMPLATE_INPUT } from '../database/default-email-template-input';

const message = '[MIGRATION] Add built in onboarding email template';
export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  await addEmailTemplate(context, SYSTEM_USER, DEFAULT_EMAIL_TEMPLATE_INPUT, false);
  logMigration.info(`${message} > done.`);
  next();
};

export const down = async (next) => {
  next();
};
