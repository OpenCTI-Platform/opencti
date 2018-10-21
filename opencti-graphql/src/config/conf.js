import nconf from 'nconf';
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';

const DEFAULT_ENV = 'development';

// Environment from NODE_ENV environment variable
nconf.add('env', {
  whitelist: ['NODE_ENV']
});

// Environment from "-e" command line parameter
nconf.add('argv', {
  e: {
    alias: 'env',
    describe: 'Execution environment'
  }
});

// Priority to command line parameter and fallback to DEFAULT_ENV
const environment = nconf.get('env') || nconf.get('NODE_ENV') || DEFAULT_ENV;
nconf.file(environment, `./config/${environment.toLowerCase()}.json`);
nconf.file('default', './config/default.json');

// Setup logger
export const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new DailyRotateFile({
      filename: 'error.log',
      dirname: nconf.get('app:logs_directory'),
      level: 'error'
    }),
    new DailyRotateFile({
      filename: 'opencti.log',
      dirname: nconf.get('app:logs_directory')
    })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple()
    })
  );
}

export default nconf;
