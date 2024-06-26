import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';
import nconf from 'nconf';
import * as R from 'ramda';
import { isEmpty } from 'ramda';
import winston, { format } from 'winston';
import ipaddr from 'ipaddr.js';
import DailyRotateFile from 'winston-daily-rotate-file';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { HttpProxyAgent } from 'http-proxy-agent';
import { ApolloError } from 'apollo-errors';
import { v4 as uuid } from 'uuid';
import * as O from '../schema/internalObject';
import * as M from '../schema/stixMetaObject';
import {
  ABSTRACT_INTERNAL_OBJECT,
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_OBJECT,
  ABSTRACT_STIX_REF_RELATIONSHIP,
} from '../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import pjson from '../../package.json';
import { ENTITY_TYPE_DECAY_RULE } from '../modules/decayRule/decayRule-types';
import { ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_TRIGGER, NOTIFICATION_NUMBER } from '../modules/notification/notification-types';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../modules/managerConfiguration/managerConfiguration-types';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import { UnknownError, UnsupportedError } from './errors';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../modules/publicDashboard/publicDashboard-types';
import { AI_BUS } from '../modules/ai/ai-types';
import { SUPPORT_BUS } from '../modules/support/support-types';

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
export const environment = nconf.get('env') || nconf.get('node_env') || process.env.NODE_ENV || DEFAULT_ENV;
const resolveEnvFile = (env) => path.join(resolvePath('config'), `${env.toLowerCase()}.json`);
export const DEV_MODE = environment !== 'production';
const externalConfigurationFile = nconf.get('conf');
export const NODE_INSTANCE_ID = nconf.get('app:node_identifier') || uuid();

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
export const appLogExtendedErrors = booleanConf('app:app_logs:extended_error_message', false);
export const extendedErrors = (metaExtension) => {
  if (appLogExtendedErrors) {
    return metaExtension;
  }
  return {};
};

const appLogTransports = [];
const logsDirname = nconf.get('app:app_logs:logs_directory');
if (appLogFileTransport) {
  const maxFiles = nconf.get('app:app_logs:logs_max_files');
  appLogTransports.push(
    new DailyRotateFile({
      filename: 'error.log',
      dirname: logsDirname,
      level: 'error',
      maxFiles,
    })
  );
  appLogTransports.push(
    new DailyRotateFile({
      filename: 'opencti.log',
      dirname: logsDirname,
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

// Setup support logs
export const SUPPORT_LOG_RELATIVE_LOCAL_DIR = '.support';
export const SUPPORT_LOG_FILE_PREFIX = 'support';
const supportLogger = winston.createLogger({
  level: 'warn',
  format: format.combine(timestamp(), format.errors({ stack: true }), format.json()),
  transports: [new DailyRotateFile({
    filename: SUPPORT_LOG_FILE_PREFIX,
    dirname: SUPPORT_LOG_RELATIVE_LOCAL_DIR,
    maxFiles: 3,
    maxSize: '10m',
    level: 'warn'
  })],
});

// Setup telemetry logs
export const TELEMETRY_LOG_RELATIVE_LOCAL_DIR = './telemetry';
export const TELEMETRY_LOG_FILE_PREFIX = 'telemetry';
const telemetryLogTransports = [new DailyRotateFile({
  dirname: TELEMETRY_LOG_RELATIVE_LOCAL_DIR,
  filename: TELEMETRY_LOG_FILE_PREFIX,
  maxFiles: 3,
  maxSize: '1m',
  level: 'info',
})];
const telemetryLogger = winston.createLogger({
  level: 'info',
  format: format.printf((info) => { return `${info.message}`; }),
  transports: telemetryLogTransports,
});

// Specific case to fail any test that produce an error log
const LOG_APP = 'APP';
const buildMetaErrors = (error) => {
  const errors = [];
  if (error instanceof ApolloError) {
    const attributes = R.dissoc('cause', error.data);
    const baseError = { name: error.name, message: error.message, stack: error.stack, attributes };
    errors.push(baseError);
    if (error.data.cause && error.data.cause instanceof Error) {
      errors.push(...buildMetaErrors(error.data.cause));
    }
  } else if (error instanceof Error) {
    const baseError = { name: error.name, message: error.message, stack: error.stack };
    errors.push(baseError);
  }
  return errors;
};
const addBasicMetaInformation = (category, error, meta) => {
  const logMeta = { ...meta };
  if (error) logMeta.errors = buildMetaErrors(error);
  return { category, version: PLATFORM_VERSION, ...logMeta };
};

export const logS3Debug = {
  debug: (message, detail) => {
    logApp._log('info', message, null, { detail });
  },
};

export const logApp = {
  _log: (level, message, error, meta = {}) => {
    if (appLogTransports.length > 0) {
      appLogger.log(level, message, addBasicMetaInformation(LOG_APP, error, { ...meta, source: 'backend' }));
    }
  },
  _logWithError: (level, messageOrError, meta = {}) => {
    const isError = messageOrError instanceof Error;
    const message = isError ? messageOrError.message : messageOrError;
    let error = null;
    if (isError) {
      if (messageOrError instanceof ApolloError) {
        error = messageOrError;
      } else {
        error = UnknownError(message, { cause: messageOrError });
      }
    }
    logApp._log(level, message, error, meta);
    supportLogger.log(level, message, addBasicMetaInformation(LOG_APP, error, { ...meta, source: 'backend' }));
  },
  debug: (message, meta = {}) => logApp._log('debug', message, null, meta),
  info: (message, meta = {}) => logApp._log('info', message, null, meta),
  warn: (messageOrError, meta = {}) => logApp._logWithError('warn', messageOrError, meta),
  error: (messageOrError, meta = {}) => logApp._logWithError('error', messageOrError, meta),
  query: (options, errCallback) => appLogger.query(options, errCallback),
};

const LOG_AUDIT = 'AUDIT';
export const logAudit = {
  _log: (level, user, operation, meta = {}) => {
    if (auditLogTransports.length > 0) {
      const metaUser = { email: user.user_email, ...user.origin };
      const logMeta = isEmpty(meta) ? { auth: metaUser } : { resource: meta, auth: metaUser };
      auditLogger.log(level, operation, addBasicMetaInformation(LOG_AUDIT, null, logMeta));
    }
  },
  info: (user, operation, meta = {}) => logAudit._log('info', user, operation, meta),
  error: (user, operation, meta = {}) => logAudit._log('error', user, operation, meta),
};

export const logFrontend = {
  _log: (level, message, error, meta = {}) => {
    const info = { ...meta, source: 'frontend' };
    appLogger.log(level, message, addBasicMetaInformation(LOG_APP, error, info));
    supportLogger.log(level, message, addBasicMetaInformation(LOG_APP, error, info));
  },
  error: (message, meta = {}) => logFrontend._log('error', message, null, meta),
};

export const logTelemetry = {
  log: (message) => {
    telemetryLogger.log('info', message);
  }
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
  if (certificates && certificates.length > 0) {
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
        throw UnknownError('Configuration failure of the CA certificate', { cause: err });
      }
    }
  }
  return { ca: [] };
};

// App
export const loadCert = (cert) => {
  if (!cert) {
    return undefined;
  }
  if (cert.startsWith('-----BEGIN')) {
    return cert;
  }
  return readFileSync(cert);
};
export const PORT = nconf.get('app:port');

const escapeRegex = (string) => {
  return string.replace(/[/\-\\^$*+?.()|[\]{}]/g, '\\$&');
};
export const isUriProxyExcluded = (hostname, exclusions) => {
  for (let index = 0; index < exclusions.length; index += 1) {
    const exclusion = exclusions[index];
    if (exclusion.includes('*')) { // Test regexp
      const pattern = escapeRegex(exclusion).replaceAll('\\*', '.*');
      const regexp = new RegExp(pattern, 'g');
      const isRegexpMatch = regexp.test(hostname);
      if (isRegexpMatch) {
        return true;
      }
    }
    // Test simple match
    if (exclusion === hostname) {
      return true;
    }
    // Test ip pattern
    if (ipaddr.isValid(hostname)) {
      try {
        const addr = ipaddr.parse(hostname);
        const cidr = ipaddr.parseCIDR(exclusion);
        if (addr.match(cidr)) {
          return true;
        }
      } catch {
        // Exclusion is not a CIDR, not important
      }
    }
  }
  return false;
};
export const getPlatformHttpProxies = () => {
  const http = nconf.get('http_proxy');
  const https = nconf.get('https_proxy');
  const exclusions = (nconf.get('no_proxy') ?? '').split(',');
  const proxyCA = nconf.get('https_proxy_ca').map((caPath) => loadCert(caPath));
  // To prevent any configuration clash with node, we reset the proxy env variables
  process.env.HTTP_PROXY = '';
  process.env.HTTPS_PROXY = '';
  process.env.NO_PROXY = '';
  const proxies = {};
  if (https) {
    proxies['https:'] = {
      build: () => new HttpsProxyAgent(https, {
        rejectUnauthorized: booleanConf('https_proxy_reject_unauthorized', false),
        ...configureCA(proxyCA)
      }),
      isExcluded: (hostname) => isUriProxyExcluded(hostname, exclusions),
    };
  }
  if (http) {
    proxies['http:'] = {
      build: () => new HttpProxyAgent(http),
      isExcluded: (hostname) => isUriProxyExcluded(hostname, exclusions),
    };
  }
  return proxies;
};
export const getPlatformHttpProxyAgent = (uri) => {
  const platformProxies = getPlatformHttpProxies();
  const targetUrl = new URL(uri);
  const targetProxy = platformProxies[targetUrl.protocol]; // Select the proxy according to target protocol
  if (targetProxy) {
    // If proxy found, check if hostname is not excluded
    if (targetProxy.isExcluded(targetUrl.hostname)) {
      return undefined;
    }
    // If not generate the agent accordingly
    return targetProxy.build();
  }
  return undefined;
};

// Playground
export const ENABLED_DEMO_MODE = booleanConf('demo_mode', false);
export const PLAYGROUND_INTROSPECTION_DISABLED = DEV_MODE ? false : booleanConf('app:graphql:playground:force_disabled_introspection', true);
export const PLAYGROUND_ENABLED = booleanConf('app:graphql:playground:enabled', true);
export const GRAPHQL_ARMOR_ENABLED = booleanConf('app:graphql:armor_enabled', true);

// Default activated managers
export const ENABLED_API = booleanConf('app:enabled', true);
export const ENABLED_TRACING = booleanConf('app:telemetry:tracing:enabled', false);
export const ENABLED_METRICS = booleanConf('app:telemetry:metrics:enabled', false);
export const ENABLED_TELEMETRY = booleanConf('app:telemetry:filigran:enabled', false);
export const ENABLED_EVENT_LOOP_MONITORING = booleanConf('app:event_loop_logs:enabled', false);
export const ENABLED_RETENTION_MANAGER = booleanConf('retention_manager:enabled', true);
export const ENABLED_NOTIFICATION_MANAGER = booleanConf('notification_manager:enabled', true);
export const ENABLED_PUBLISHER_MANAGER = booleanConf('publisher_manager:enabled', true);
export const ENABLED_TELEMETRY_MANAGER = booleanConf('telemetry_manager:enabled', true);
export const ENABLED_CONNECTOR_MANAGER = booleanConf('connector_manager:enabled', true);
export const ENABLED_FILE_INDEX_MANAGER = booleanConf('file_index_manager:enabled', true);

// Default deactivated managers
export const ENABLED_EXPIRED_MANAGER = booleanConf('expiration_scheduler:enabled', false);
export const ENABLED_TASK_SCHEDULER = booleanConf('task_scheduler:enabled', false);
export const ENABLED_SYNC_MANAGER = booleanConf('sync_manager:enabled', false);
export const ENABLED_INGESTION_MANAGER = booleanConf('ingestion_manager:enabled', false);
export const ENABLED_RULE_ENGINE = booleanConf('rule_engine:enabled', false);
export const ENABLED_HISTORY_MANAGER = booleanConf('history_manager:enabled', false);
export const ENABLED_PLAYBOOK_MANAGER = booleanConf('playbook_manager:enabled', false);

// Default Accounts management
export const ACCOUNT_STATUS_ACTIVE = 'Active';
export const ACCOUNT_STATUS_EXPIRED = 'Expired';
const computeAccountStatusChoices = () => {
  const statusesDefinition = nconf.get('app:locked_account_statuses');
  return {
    [ACCOUNT_STATUS_ACTIVE]: 'All good folks',
    [ACCOUNT_STATUS_EXPIRED]: 'Your account has expired. If you would like to reactivate your account, please contact your administrator.',
    ...statusesDefinition
  };
};
export const ACCOUNT_STATUSES = computeAccountStatusChoices();
export const computeDefaultAccountStatus = () => {
  const defaultConf = nconf.get('app:account_statuses_default');
  if (defaultConf) {
    const accountStatus = ACCOUNT_STATUSES[defaultConf];
    if (accountStatus) {
      return defaultConf;
    }
    throw UnsupportedError('Invalid default_initialize_account_status configuration', { default: defaultConf, statuses: ACCOUNT_STATUSES });
  }
  return ACCOUNT_STATUS_ACTIVE;
};
export const DEFAULT_ACCOUNT_STATUS = computeDefaultAccountStatus();

// Default settings
const platformState = { stopping: false };
export const getStoppingState = () => platformState.stopping;
export const setStoppingState = (state) => {
  platformState.stopping = state;
};

export const DISABLED_FEATURE_FLAGS = nconf.get('app:disabled_dev_features') ?? [];
export const isFeatureEnabled = (feature) => {
  const isActivated = DISABLED_FEATURE_FLAGS.length === 0 || !DISABLED_FEATURE_FLAGS.includes(feature);
  if (!isActivated) {
    logApp.info('[FEATURE-FLAG] Deactivated feature still in development', { feature });
  }
  return isActivated;
};

export const REDIS_PREFIX = nconf.get('redis:namespace') ? `${nconf.get('redis:namespace')}:` : '';
export const TOPIC_PREFIX = `${REDIS_PREFIX}_OPENCTI_DATA_`;
export const TOPIC_CONTEXT_PREFIX = `${REDIS_PREFIX}_OPENCTI_CONTEXT_`;
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
  [O.ENTITY_TYPE_RULE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}RULE_EDIT_TOPIC`,
  },
  [O.ENTITY_TYPE_ROLE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ROLE_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ROLE_ADDED_TOPIC`,
  },
  [O.ENTITY_TYPE_USER]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}USER_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}USER_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_WORKSPACE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}WORKSPACE_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}WORKSPACE_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_PUBLIC_DASHBOARD]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}PUBLIC_DASHBOARD_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}PUBLIC_DASHBOARD_ADDED_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}PUBLIC_DASHBOARD_DELETE_TOPIC`,
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
    DELETE_TOPIC: `${TOPIC_PREFIX}STREAM_COLLECTION_DELETE_TOPIC`,
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
    CONTEXT_TOPIC: `${TOPIC_CONTEXT_PREFIX}INTERNAL_OBJECT_CONTEXT_TOPIC`,
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
  [ABSTRACT_STIX_REF_RELATIONSHIP]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ABSTRACT_STIX_REF_RELATIONSHIP_EDIT_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}ABSTRACT_STIX_REF_RELATIONSHIP_DELETE_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ABSTRACT_STIX_REF_RELATIONSHIP_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_DECAY_RULE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_DECAY_RULE_EDIT_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_DECAY_RULE_DELETE_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_DECAY_RULE_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_MANAGER_CONFIGURATION]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_MANAGER_CONFIGURATION_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_MANAGER_CONFIGURATION_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_NOTIFICATION]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_NOTIFICATION_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_NOTIFICATION_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_TRIGGER]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_TRIGGER_EDIT_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_TRIGGER_DELETE_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_TRIGGER_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_NOTIFIER]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_NOTIFIER_EDIT_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_NOTIFIER_DELETE_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_NOTIFIER_ADDED_TOPIC`,
  },
  [NOTIFICATION_NUMBER]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_NOTIFICATION_NUMBER_EDIT_TOPIC`,
  },
  [AI_BUS]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_AI_BUS_EDIT_TOPIC`,
  },
  [SUPPORT_BUS]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_SUPPORT_PACKAGE_EDIT_TOPIC`,
  },
};

export const getBusTopicForEntityType = (entityType) => {
  return BUS_TOPICS[entityType];
};

export default nconf;
