import { logMigration } from '../config/conf';

const message = '[MIGRATION] Skip Attack Pattern / Course of Action standard_id case-insensitive duplicate merge fix';

export const up = async (next: (error?: Error) => void) => {
  const start = new Date().getTime();
  logMigration.info(`${message} > started`);
  logMigration.info(`${message} > done in ${new Date().getTime() - start} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
