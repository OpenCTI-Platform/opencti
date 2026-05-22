import { logMigration } from '../config/conf';

const message = '[MIGRATION] migration title';

export const up = async (next: any) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  // do your migration
  // see src/migration/README.md for best practices
  // if there is a loop, add a logMigration.info to display expected number and progress (ex: "processing 2/100 Indicators")
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: any) => {
  next();
};
