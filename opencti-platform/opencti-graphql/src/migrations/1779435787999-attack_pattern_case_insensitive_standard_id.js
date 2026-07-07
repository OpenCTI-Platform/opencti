import { logMigration } from '../config/conf';

const message = '[MIGRATION][Replaced by Data sanity manager operation] Attack Pattern / Course of Action standard_id case-insensitive rewrite';

export const up = async (next) => {
  const start = new Date().getTime();
  logMigration.info(`${message} > started`);

  logMigration.info(
    `${message} > done in ${new Date().getTime() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
