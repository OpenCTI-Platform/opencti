import nconf from 'nconf';
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import dotenv from 'dotenv';
// noinspection NodeJsCodingAssistanceForCoreModules
import path from 'path';

export const ROLE_ADMIN = 'ROLE_ADMIN';
export const ROLE_USER = 'ROLE_USER';
export const OPENCTI_TOKEN = 'opencti_token';
export const OPENCTI_WEB_TOKEN = 'Default';
export const OPENCTI_ISSUER = 'OpenCTI';
export const OPENCTI_DEFAULT_DURATION = 'P99Y';

export const BUS_TOPICS = {
  Settings: {
    EDIT_TOPIC: 'SETTINGS_EDIT_TOPIC',
    ADDED_TOPIC: 'SETTINGS_ADDED_TOPIC'
  },
  User: {
    EDIT_TOPIC: 'USER_EDIT_TOPIC',
    ADDED_TOPIC: 'USER_ADDED_TOPIC'
  },
  Group: {
    EDIT_TOPIC: 'GROUP_EDIT_TOPIC',
    ADDED_TOPIC: 'GROUP_ADDED_TOPIC'
  },
  MarkingDefinition: {
    EDIT_TOPIC: 'MARKING_DEFINITION_EDIT_TOPIC',
    ADDED_TOPIC: 'MARKING_DEFINITION_ADDED_TOPIC'
  },
  KillChainPhase: {
    EDIT_TOPIC: 'KILL_CHAIN_PHASE_EDIT_TOPIC',
    ADDED_TOPIC: 'KILL_CHAIN_PHASE_ADDED_TOPIC'
  },
  Identity: {
    EDIT_TOPIC: 'IDENTITY_EDIT_TOPIC',
    ADDED_TOPIC: 'IDENTITY_ADDED_TOPIC'
  },
  ThreatActor: {
    EDIT_TOPIC: 'THREAT_ACTOR_EDIT_TOPIC',
    ADDED_TOPIC: 'THREAT_ACTOR_ADDED_TOPIC'
  },
  IntrusionSet: {
    EDIT_TOPIC: 'INTRUSION_SET_EDIT_TOPIC',
    ADDED_TOPIC: 'INTRUSION_SET_ADDED_TOPIC'
  },
  Malware: {
    EDIT_TOPIC: 'MALWARE_EDIT_TOPIC',
    ADDED_TOPIC: 'MALWARE_ADDED_TOPIC'
  },
  Report: {
    EDIT_TOPIC: 'REPORT_EDIT_TOPIC',
    ADDED_TOPIC: 'REPORT_ADDED_TOPIC'
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
  },
  c: {
    alias: 'conf',
    describe: 'Configuration file'
  }
});

// Priority to command line parameter and fallback to DEFAULT_ENV
const DEFAULT_ENV = 'production';
const DEFAULT_CONF_PATH = path.join(__dirname, '../../config/');
const environment = nconf.get('env') || nconf.get('NODE_ENV') || DEFAULT_ENV;
const externalConfigurationFile = nconf.get('conf');
let configurationFile;
if (externalConfigurationFile) {
  configurationFile = externalConfigurationFile;
} else {
  configurationFile = `${DEFAULT_CONF_PATH}${environment.toLowerCase()}.json`;
}

nconf.file(environment, configurationFile);
nconf.file('default', `${DEFAULT_CONF_PATH}/default.json`);

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

export const DEV_MODE = environment !== 'production';
if (DEV_MODE) {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
      level: 'debug'
    })
  );
}

// eslint-disable-next-line
console.log(`🚀 OpenCTI started in ${environment} mode with ${externalConfigurationFile ? 'external' : 'embedded'} file`);
export default nconf;
