import { logApp } from '../config/conf';

const message = '[MIGRATION] migration title';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  // do your migration
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
