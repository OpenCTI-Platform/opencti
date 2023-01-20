import { lstatSync, readFileSync } from 'node:fs';
import nconf from 'nconf';
import * as R from 'ramda';
import { isEmpty } from 'ramda';
import winston, { format } from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'node:path';
import * as O from '../schema/internalObject';
import * as M from '../schema/stixMetaObject';
import {
  ABSTRACT_INTERNAL_OBJECT,
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_OBJECT,
} from '../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import pjson from '../../package.json';
import { ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';

// https://golang.org/src/crypto/x509/root_linux.go
const LINUX_CERTFILES = [
  '/etc/ssl/certs/ca-certificates.crt', // Debian/Ubuntu/Gentoo etc.
  '/etc/pki/tls/certs/ca-bundle.crt', // Fedora/RHEL 6
  '/etc/ssl/ca-bundle.pem', // OpenSUSE
  '/etc/pki/tls/cacert.pem', // OpenELEC
  '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', // CentOS/RHEL 7
  '/etc/ssl/cert.pem',
];

const DEFAULT_ENV = 'production';
export const OPENCTI_SESSION = 'opencti_session';
export const TOPIC_PREFIX = 'OPENCTI_DATA_';
export const TOPIC_CONTEXT_PREFIX = 'OPENCTI_CONTEXT_';
export const BUS_TOPICS = {
  [O.ENTITY_TYPE_SETTINGS]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}SETTINGS_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}SETTINGS_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_ENTITY_SETTING]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_SETTING_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ENTITY_SETTING_ADDED_TOPIC`,
  },
  [O.ENTITY_TYPE_GROUP]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}GROUP_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}GROUP_ADDED_TOPIC`,
  },
  [O.ENTITY_TYPE_ROLE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ROLE_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ROLE_ADDED_TOPIC`,
  },
  [O.ENTITY_TYPE_USER]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}USER_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}USER_ADDED_TOPIC`,
  },
  [O.ENTITY_TYPE_WORKSPACE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}WORKSPACE_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}WORKSPACE_ADDED_TOPIC`,
  },
  [M.ENTITY_TYPE_LABEL]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}LABEL_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}LABEL_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_VOCABULARY]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}VOCABULARY_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}VOCABULARY_ADDED_TOPIC`,
  },
  [O.ENTITY_TYPE_CONNECTOR]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}CONNECTOR_EDIT_TOPIC`,
  },
  [O.ENTITY_TYPE_TAXII_COLLECTION]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}TAXII_COLLECTION_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}TAXII_COLLECTION_ADDED_TOPIC`,
  },
  [O.ENTITY_TYPE_STREAM_COLLECTION]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}STREAM_COLLECTION_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}STREAM_COLLECTION_ADDED_TOPIC`,
  },
  [O.ENTITY_TYPE_SYNC]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}SYNC_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}SYNC_ADDED_TOPIC`,
  },
  [M.ENTITY_TYPE_MARKING_DEFINITION]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}MARKING_DEFINITION_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}MARKING_DEFINITION_ADDED_TOPIC`,
  },
  [M.ENTITY_TYPE_LABEL]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}LABEL_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}LABEL_ADDED_TOPIC`,
  },
  [M.ENTITY_TYPE_EXTERNAL_REFERENCE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}EXTERNAL_REFERENCE_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}EXTERNAL_REFERENCE_ADDED_TOPIC`,
  },
  [M.ENTITY_TYPE_KILL_CHAIN_PHASE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}KILL_CHAIN_PHASE_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}KILL_CHAIN_PHASE_ADDED_TOPIC`,
  },
  [ABSTRACT_INTERNAL_OBJECT]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}INTERNAL_OBJECT_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}INTERNAL_OBJECT_ADDED_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}INTERNAL_OBJECT_DELETE_TOPIC`,
  },
  [ABSTRACT_STIX_OBJECT]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}STIX_OBJECT_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}STIX_OBJECT_ADDED_TOPIC`,
  },
  [ABSTRACT_STIX_CORE_OBJECT]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}STIX_CORE_OBJECT_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}STIX_CORE_OBJECT_ADDED_TOPIC`,
  },
  [ABSTRACT_STIX_DOMAIN_OBJECT]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}STIX_DOMAIN_OBJECT_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}STIX_DOMAIN_OBJECT_ADDED_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}STIX_DOMAIN_OBJECT_DELETE_TOPIC`,
    CONTEXT_TOPIC: `${TOPIC_CONTEXT_PREFIX}STIX_DOMAIN_OBJECT_CONTEXT_TOPIC`,
  },
  [ABSTRACT_STIX_CYBER_OBSERVABLE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}STIX_CYBER_OBSERVABLE_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}STIX_CYBER_OBSERVABLE_ADDED_TOPIC`,
  },
  [ABSTRACT_STIX_CORE_RELATIONSHIP]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}STIX_CORE_RELATIONSHIP_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}STIX_CORE_RELATIONSHIP_ADDED_TOPIC`,
  },
  [STIX_SIGHTING_RELATIONSHIP]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}STIX_SIGHTING_RELATIONSHIP_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}STIX_SIGHTING_RELATIONSHIP_ADDED_TOPIC`,
  },
  [ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}STIX_CYBER_OBSERVABLE_RELATIONSHIP_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}STIX_CYBER_OBSERVABLE_RELATIONSHIP_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_NOTIFICATION]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_NOTIFICATION_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_NOTIFICATION_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_TRIGGER]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_TRIGGER_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_TRIGGER_ADDED_TOPIC`,
  },
};

export const PLATFORM_VERSION = pjson.version;

export const booleanConf = (key, defaultValue = true) => {
  const configValue = nconf.get(key);
  if (R.isEmpty(configValue) || R.isNil(configValue)) {
    return defaultValue;
  }
  return configValue === true || configValue === 'true';
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

const { timestamp } = format;
const currentPath = process.env.INIT_CWD || process.cwd();
const resolvePath = (relativePath) => path.join(currentPath, relativePath);
const environment = nconf.get('env') || nconf.get('node_env') || process.env.NODE_ENV || DEFAULT_ENV;
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

// Setup application logApp
const appLogLevel = nconf.get('app:app_logs:logs_level');
const appLogFileTransport = booleanConf('app:app_logs:logs_files', true);
const appLogConsoleTransport = booleanConf('app:app_logs:logs_console', true);
const appLogTransports = [];
if (appLogFileTransport) {
  const dirname = nconf.get('app:app_logs:logs_directory');
  const maxFiles = nconf.get('app:app_logs:logs_max_files');
  appLogTransports.push(
    new DailyRotateFile({
      filename: 'error.log',
      dirname,
      level: 'error',
      maxFiles,
    })
  );
  appLogTransports.push(
    new DailyRotateFile({
      filename: 'opencti.log',
      dirname,
      maxFiles,
    })
  );
}
if (appLogConsoleTransport) {
  appLogTransports.push(new winston.transports.Console());
}
const appLogger = winston.createLogger({
  level: appLogLevel,
  format: format.combine(timestamp(), format.errors({ stack: true }), format.json()),
  transports: appLogTransports,
});

// Setup audit log logApp
const auditLogFileTransport = booleanConf('app:audit_logs:logs_files', true);
const auditLogConsoleTransport = booleanConf('app:audit_logs:logs_console', true);
const auditLogTransports = [];
if (auditLogFileTransport) {
  const dirname = nconf.get('app:audit_logs:logs_directory');
  const maxFiles = nconf.get('app:audit_logs:logs_max_files');
  auditLogTransports.push(
    new DailyRotateFile({
      filename: 'audit.log',
      dirname,
      maxFiles,
    })
  );
}
if (auditLogConsoleTransport) {
  auditLogTransports.push(new winston.transports.Console());
}
const auditLogger = winston.createLogger({
  level: 'info',
  format: format.combine(timestamp(), format.errors({ stack: true }), format.json()),
  transports: auditLogTransports,
});

// Specific case to fail any test that produce an error log
if (environment === 'test') {
  appLogger.on('data', (log) => {
    if (log.level === 'error') throw Error(log.message);
  });
}
const LOG_APP = 'APP';
const addBasicMetaInformation = (category, meta) => {
  const logInformation = { ...meta, category, version: PLATFORM_VERSION };
  const infoEntries = Object.entries(logInformation);
  const logMeta = {};
  for (let entry = 0; entry < infoEntries.length; entry += 1) {
    const [k, v] = infoEntries[entry];
    if (v instanceof Error) {
      const basicError = { name: v.name, message: v.message, stack: v.stack };
      if (v._error) { // Apollo error
        logMeta[k] = { name: v.name, message: v.message, stack: basicError.stack, context: v.data };
      } else { // Standard error
        logMeta[k] = { ...basicError, context: {} };
      }
    } else {
      logMeta[k] = v;
    }
  }
  return logMeta;
};
export const logApp = {
  _log: (level, message, meta = {}) => {
    if (appLogTransports.length > 0) {
      appLogger.log(level, message, addBasicMetaInformation(LOG_APP, meta));
    }
  },
  debug: (message, meta = {}) => logApp._log('debug', message, meta),
  info: (message, meta = {}) => logApp._log('info', message, meta),
  warn: (message, meta = {}) => logApp._log('warn', message, meta),
  error: (message, meta = {}) => logApp._log('error', message, meta),
};

const LOG_AUDIT = 'AUDIT';
export const logAudit = {
  _log: (level, user, operation, meta = {}) => {
    if (auditLogTransports.length > 0) {
      const metaUser = { email: user.user_email, ...user.origin };
      const logMeta = isEmpty(meta) ? { auth: metaUser } : { resource: meta, auth: metaUser };
      auditLogger.log(level, operation, addBasicMetaInformation(LOG_AUDIT, logMeta));
    }
  },
  info: (user, operation, meta = {}) => logAudit._log('info', user, operation, meta),
  error: (user, operation, meta = {}) => logAudit._log('error', user, operation, meta),
};

const BasePathConfig = nconf.get('app:base_path')?.trim() ?? '';
const AppBasePath = BasePathConfig.endsWith('/') ? BasePathConfig.slice(0, -1) : BasePathConfig;
export const basePath = isEmpty(AppBasePath) || AppBasePath.startsWith('/') ? AppBasePath : `/${AppBasePath}`;

const BasePathUrl = nconf.get('app:base_url')?.trim() ?? '';
const baseUrl = BasePathUrl.endsWith('/') ? BasePathUrl.slice(0, -1) : BasePathUrl;

export const getBaseUrl = (req) => {
  // If base url is defined, take it in priority
  if (baseUrl) {
    // Always append base path to the uri
    return baseUrl + basePath;
  }
  // If no base url, try to infer the uri from the request
  if (req) {
    const [, port] = req.headers.host ? req.headers.host.split(':') : [];
    const isCustomPort = port !== '80' && port !== '443';
    const httpPort = isCustomPort && port ? `:${port}` : '';
    return `${req.protocol}://${req.hostname}${httpPort}${basePath}`;
  }
  // If no base url and no request, send only the base path
  return basePath;
};

export const configureCA = (certificates) => {
  if (certificates && certificates.length) {
    return { ca: certificates };
  }
  // eslint-disable-next-line no-restricted-syntax
  for (const cert of LINUX_CERTFILES) {
    try {
      if (lstatSync(cert).isFile()) {
        return { ca: [readFileSync(cert)] };
      }
    } catch (err) {
      if (err.code === 'ENOENT') {
        // For this error, try the next one.
      } else {
        throw err;
      }
    }
  }
  return { ca: [] };
};

// App
export const PORT = nconf.get('app:port');

// Default activated managers
export const ENABLED_API = booleanConf('app:enabled', true);
export const ENABLED_TRACING = booleanConf('app:telemetry:tracing:enabled', false);
export const ENABLED_METRICS = booleanConf('app:telemetry:metrics:enabled', false);
export const ENABLED_RETENTION_MANAGER = booleanConf('retention_manager:enabled', true);
export const ENABLED_NOTIFICATION_MANAGER = booleanConf('notification_manager:enabled', true);
export const ENABLED_PUBLISHER_MANAGER = booleanConf('publisher_manager:enabled', true);
export const ENABLED_CONNECTOR_MANAGER = booleanConf('connector_manager:enabled', true);
// Default deactivated managers
export const ENABLED_EXPIRED_MANAGER = booleanConf('expiration_scheduler:enabled', false);
export const ENABLED_TASK_SCHEDULER = booleanConf('task_scheduler:enabled', false);
export const ENABLED_SYNC_MANAGER = booleanConf('sync_manager:enabled', false);
export const ENABLED_RULE_ENGINE = booleanConf('rule_engine:enabled', false);
export const ENABLED_HISTORY_MANAGER = booleanConf('history_manager:enabled', false);
export const ENABLED_CACHING = booleanConf('redis:use_as_cache', false);

export const ELASTIC_CREATION_PATTERN = nconf.get('elasticsearch:index_creation_pattern');

const platformState = { stopping: false };
export const getStoppingState = () => platformState.stopping;
export const setStoppingState = (state) => {
  platformState.stopping = state;
};

export default nconf;
