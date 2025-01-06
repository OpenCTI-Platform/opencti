import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { initFintelTemplates } from '../modules/fintelTemplate/fintelTemplate-domain';

const message = '[MIGRATION] Add built-in Fintel templates';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  await initFintelTemplates(context, SYSTEM_USER);
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
