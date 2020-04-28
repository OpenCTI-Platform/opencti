import nconf from 'nconf';
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'path';

const DEFAULT_ENV = 'production';
export const OPENCTI_TOKEN = 'opencti_token';
export const OPENCTI_WEB_TOKEN = 'Default';
export const OPENCTI_ISSUER = 'OpenCTI';
export const OPENCTI_DEFAULT_DURATION = 'P99Y';
export const BUS_TOPICS = {
  Settings: {
    EDIT_TOPIC: 'SETTINGS_EDIT_TOPIC',
    ADDED_TOPIC: 'SETTINGS_ADDED_TOPIC',
  },
  Role: {
    EDIT_TOPIC: 'ROLE_EDIT_TOPIC',
    ADDED_TOPIC: 'ROLE_ADDED_TOPIC',
  },
  Tag: {
    EDIT_TOPIC: 'TAG_EDIT_TOPIC',
    ADDED_TOPIC: 'TAG_ADDED_TOPIC',
  },
  Connector: {
    EDIT_TOPIC: 'CONNECTOR_EDIT_TOPIC',
  },
  StixEntity: {
    EDIT_TOPIC: 'STIX_ENTITY_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_ENTITY_ADDED_TOPIC',
  },
  StixDomainEntity: {
    EDIT_TOPIC: 'STIX_DOMAIN_ENTITY_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_DOMAIN_ENTITY_ADDED_TOPIC',
  },
  StixRelation: {
    EDIT_TOPIC: 'STIX_RELATION_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_RELATION_ADDED_TOPIC',
  },
  StixObservableRelation: {
    EDIT_TOPIC: 'STIX_OBSERVABLE_RELATION_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_OBSERVABLE_RELATION_ADDED_TOPIC',
  },
  StixObservable: {
    EDIT_TOPIC: 'STIX_OBSERVABLE_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_OBSERVABLE_ADDED_TOPIC',
  },
  Workspace: {
    EDIT_TOPIC: 'WORKSPACE_EDIT_TOPIC',
    ADDED_TOPIC: 'WORKSPACE_ADDED_TOPIC',
  },
  MarkingDefinition: {
    EDIT_TOPIC: 'MARKING_DEFINITION_EDIT_TOPIC',
    ADDED_TOPIC: 'MARKING_DEFINITION_ADDED_TOPIC',
  },
  ExternalReference: {
    EDIT_TOPIC: 'EXTERNAL_REFERENCE_EDIT_TOPIC',
    ADDED_TOPIC: 'EXTERNAL_REFERENCE_ADDED_TOPIC',
  },
  KillChainPhase: {
    EDIT_TOPIC: 'KILL_CHAIN_PHASE_EDIT_TOPIC',
    ADDED_TOPIC: 'KILL_CHAIN_PHASE_ADDED_TOPIC',
  },
  Group: {
    EDIT_TOPIC: 'GROUP_EDIT_TOPIC',
    ADDED_TOPIC: 'GROUP_ADDED_TOPIC',
  },
};

// Environment from NODE_ENV environment variable
nconf.env({ separator: '__', lowerCase: true, parseValues: true });

// Environment from "-e" command line parameter
nconf.add('argv', {
  e: {
    alias: 'env',
    describe: 'Execution environment',
  },
  c: {
    alias: 'conf',
    describe: 'Configuration file',
  },
});

const currentPath = process.env.INIT_CWD || process.cwd();
const resolvePath = (relativePath) => path.join(currentPath, relativePath);
const environment = nconf.get('env') || nconf.get('node_env') || DEFAULT_ENV;
const resolveEnvFile = (env) => path.join(resolvePath('config'), `${env.toLowerCase()}.json`);
export const DEV_MODE = environment !== 'production';
const externalConfigurationFile = nconf.get('conf');
let configurationFile;
if (externalConfigurationFile) {
  configurationFile = externalConfigurationFile;
} else {
  configurationFile = resolveEnvFile(environment);
}

nconf.file(environment, configurationFile);
nconf.file('default', resolveEnvFile('default'));

// Setup logger
const loggerInstance = winston.createLogger({
  level: nconf.get('app:logs_level'),
  format: winston.format.json(),
  transports: [
    new DailyRotateFile({
      filename: 'error.log',
      dirname: nconf.get('app:logs'),
      level: 'error',
      maxFiles: '30',
    }),
    new DailyRotateFile({
      filename: 'opencti.log',
      dirname: nconf.get('app:logs'),
      maxFiles: '30',
    }),
    new winston.transports.Console({
      format: winston.format.json(),
    }),
  ],
});

// Specific case to fail any test that produce an error log
if (environment === 'test') {
  loggerInstance.on('data', (log) => {
    if (log.level === 'error') throw Error(log.message);
  });
}

export const logger = loggerInstance;
export default nconf;
