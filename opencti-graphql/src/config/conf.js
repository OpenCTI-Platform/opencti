import nconf from 'nconf';
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
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
  Connector: {
    EDIT_TOPIC: 'CONNECTOR_EDIT_TOPIC',
  },
  StixDomainEntity: {
    EDIT_TOPIC: 'STIX_DOMAIN_ENTITY_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_DOMAIN_ENTITY_ADDED_TOPIC'
  },
  StixRelation: {
    EDIT_TOPIC: 'STIX_RELATION_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_RELATION_ADDED_TOPIC'
  },
  StixObservable: {
    EDIT_TOPIC: 'STIX_OBSERVABLE_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_OBSERVABLE_ADDED_TOPIC'
  },
  Workspace: {
    EDIT_TOPIC: 'WORKSPACE_EDIT_TOPIC',
    ADDED_TOPIC: 'WORKSPACE_ADDED_TOPIC'
  },
  MarkingDefinition: {
    EDIT_TOPIC: 'MARKING_DEFINITION_EDIT_TOPIC',
    ADDED_TOPIC: 'MARKING_DEFINITION_ADDED_TOPIC'
  },
  ExternalReference: {
    EDIT_TOPIC: 'EXTERNAL_REFERENCE_EDIT_TOPIC',
    ADDED_TOPIC: 'EXTERNAL_REFERENCE_ADDED_TOPIC'
  },
  KillChainPhase: {
    EDIT_TOPIC: 'KILL_CHAIN_PHASE_EDIT_TOPIC',
    ADDED_TOPIC: 'KILL_CHAIN_PHASE_ADDED_TOPIC'
  }
};

// Environment from NODE_ENV environment variable
nconf.env({ separator: '__', lowerCase: true,  parseValues: true });

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
const environment = nconf.get('env') || nconf.get('node_env') || DEFAULT_ENV;
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
      dirname: nconf.get('app:logs'),
      level: 'error'
    }),
    new DailyRotateFile({
      filename: 'opencti.log',
      dirname: nconf.get('app:logs')
    })
  ]
});

export const DEV_MODE = environment !== 'production';
if (DEV_MODE) {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
      level: 'info'
    })
  );
}

// eslint-disable-next-line
console.log(`🚀 OpenCTI started in ${environment} mode with ${externalConfigurationFile ? 'external' : 'embedded'} file`);
export const isAppRealTime =
  nconf.get('app:reactive') && JSON.parse(nconf.get('app:reactive'));
export default nconf;
