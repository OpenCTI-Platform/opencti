import { logMigration } from '../config/conf';

const message = '[MIGRATION] migration title';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  // do your migration
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
