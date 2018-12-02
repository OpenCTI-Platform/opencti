import nconf from 'nconf';
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import dotenv from 'dotenv';

export const ROLE_ADMIN = 'ROLE_ADMIN';
export const ROLE_USER = 'ROLE_USER';
export const OPENCTI_TOKEN = 'opencti_token';
export const OPENCTI_WEB_TOKEN = 'Default';
export const OPENCTI_ISSUER = 'OpenCTI';
export const OPENCTI_DEFAULT_DURATION = 'P99Y';

export const BUS_TOPICS = {
  User: {
    EDIT_TOPIC: 'USER_EDIT_TOPIC',
    ADDED_TOPIC: 'USER_ADDED_TOPIC'
  },
  Malware: {
    EDIT_TOPIC: 'MALWARE_EDIT_TOPIC',
    ADDED_TOPIC: 'MALWARE_ADDED_TOPIC'
  }
};

// Initialize the environment.
dotenv.config();

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
const DEFAULT_ENV = 'production';
const environment = nconf.get('env') || nconf.get('NODE_ENV') || DEFAULT_ENV;
export const DEV_MODE = environment !== 'production';
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

if (DEV_MODE) {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
      level: 'debug'
    })
  );
}

logger.info(`🚀 OpenCTI started in ${environment} mode`);
export default nconf;
