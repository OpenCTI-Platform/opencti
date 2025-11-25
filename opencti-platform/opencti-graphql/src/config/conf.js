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
import { v4 as uuid } from 'uuid';
import { GraphQLError } from 'graphql/index';
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
import { UNKNOWN_ERROR, UnknownError, UnsupportedError } from './errors';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../modules/publicDashboard/publicDashboard-types';
import { AI_BUS } from '../modules/ai/ai-types';
import { SUPPORT_BUS } from '../modules/support/support-types';
import { ENTITY_TYPE_EXCLUSION_LIST } from '../modules/exclusionList/exclusionList-types';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../modules/fintelTemplate/fintelTemplate-types';
import { ENTITY_TYPE_DISSEMINATION_LIST } from '../modules/disseminationList/disseminationList-types';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { ENTITY_TYPE_PIR } from '../modules/pir/pir-types';
import { ENTITY_TYPE_FINTEL_DESIGN } from '../modules/fintelDesign/fintelDesign-types';
import { ENTITY_TYPE_EMAIL_TEMPLATE } from '../modules/emailTemplate/emailTemplate-types';

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
const LOG_APP = 'APP';
const LOG_AUDIT = 'AUDIT';

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
export const PLATFORM_INSTANCE_ID = `platform:instance:${NODE_INSTANCE_ID}`;

let configurationFile;
if (externalConfigurationFile) {
  configurationFile = externalConfigurationFile;
} else {
  configurationFile = resolveEnvFile(environment);
}

nconf.file(environment, configurationFile);
nconf.file('default', resolveEnvFile('default'));

// Setup SSO/SAML auth_payload_body_size
// Default limit is '100kb' based on https://expressjs.com/en/resources/middleware/body-parser.html
export const AUTH_PAYLOAD_BODY_SIZE = nconf.get('app:auth_payload_body_size') ?? null;

// Setup application logApp
const appLogLevel = nconf.get('app:app_logs:logs_level');
const appLogFileTransport = booleanConf('app:app_logs:logs_files', true);
const appLogConsoleTransport = booleanConf('app:app_logs:logs_console', true);
export const appLogLevelMaxDepthSize = nconf.get('app:app_logs:control:max_depth_size') ?? 10;
export const appLogLevelMaxDepthKeys = nconf.get('app:app_logs:control:max_depth_keys') ?? 100;
export const appLogLevelMaxArraySize = nconf.get('app:app_logs:control:max_array_size') ?? 50;
export const appLogLevelMaxStringSize = nconf.get('app:app_logs:control:max_string_size') ?? 5000;
export const appLogExtendedErrors = booleanConf('app:app_logs:extended_error_message', false);
export const extendedErrors = (metaExtension) => {
  if (appLogExtendedErrors) {
    return metaExtension;
  }
  return {};
};
const convertErrorObject = (error, acc, current_depth) => {
  if (error instanceof GraphQLError) {
    const extensions = error.extensions ?? {};
    const extensionsData = extensions.data ?? {};
    const attributes = prepareLogMetadataComplexityWrapper(extensionsData, acc, current_depth);
    return { name: extensions.code ?? error.name, code: extensions.code, message: error.message, stack: error.stack, attributes };
  }
  if (error instanceof Error) {
    return { name: error.name, code: UNKNOWN_ERROR, message: error.message, stack: error.stack };
  }
  return error;
};
const prepareLogMetadataComplexityWrapper = (obj, acc, current_depth = 0) => {
  const maxDepth = current_depth > appLogLevelMaxDepthSize;
  const maxKeys = acc.current_nb_key > appLogLevelMaxDepthKeys;
  const isAKeyFunction = typeof obj === 'function';
  if (obj !== null) {
    // If complexity is too much or function found.
    // return null value
    if (maxDepth || maxKeys || isAKeyFunction) {
      return null;
    }
    // If array, try to limit the number of elements
    if (Array.isArray(obj)) {
      // Create a new array with a limited size
      const limitedArray = obj.slice(0, appLogLevelMaxArraySize);
      // Recursively process each item in the truncated array
      const processedArray = [];
      for (let i = 0; i < limitedArray.length; i += 1) {
        const cleanItem = prepareLogMetadataComplexityWrapper(limitedArray[i], acc, current_depth);
        if (cleanItem) {
          processedArray[i] = cleanItem;
        }
      }
      return processedArray;
    }
    if (typeof obj === 'string' && obj.length > appLogLevelMaxStringSize) {
      return `${obj.substring(0, appLogLevelMaxStringSize - 3)}...`;
    }
    if (typeof obj === 'object') {
      const workingObject = convertErrorObject(obj, acc, current_depth);
      // Create a new object to hold the processed properties
      const limitedObject = {};
      const keys = Object.keys(workingObject); // Get the keys of the object
      const newDepth = current_depth + 1;
      for (let i = 0; i < keys.length; i += 1) {
        acc.current_nb_key += 1;
        const key = keys[i];
        limitedObject[key] = prepareLogMetadataComplexityWrapper(workingObject[key], acc, newDepth);
        // If data is null, remove the key
        if (!limitedObject[key]) {
          delete limitedObject[key];
        }
      }
      return limitedObject;
    }
  }
  return obj;
};
// Prepare the data - Format the errors and limit complexity
export const prepareLogMetadata = (obj, extra = {}) => {
  const acc = { current_nb_key: 0 };
  const protectedObj = prepareLogMetadataComplexityWrapper(obj, acc);
  return { ...extra, ...protectedObj, version: PLATFORM_VERSION };
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

const migrationLogger = winston.createLogger({
  level: 'debug',
  format: format.combine(timestamp(), format.errors({ stack: true }), format.json()),
  transports: appLogTransports,
});

const appLogger = winston.createLogger({
  level: appLogLevel,
  format: format.combine(timestamp(), format.errors({ stack: true }), format.json()),
  transports: appLogTransports,
});

// Setup audit log logApp
const auditLogFileTransport = booleanConf('app:audit_logs:logs_files', true);
const auditLogConsoleTransport = booleanConf('app:audit_logs:logs_console', true);
export const auditRequestHeaderToKeep = nconf.get('app:audit_logs:trace_request_headers') ?? ['user-agent', 'x-forwarded-for'];

// Gather all request header that are configured to be added to audit or activity logs.
export const getRequestAuditHeaders = (req) => {
  const sourceIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const allHeadersRequested = R.mergeAll((auditRequestHeaderToKeep).map((header) => ({ [header]: req.header(header) })));
  return { ...allHeadersRequested, ip: sourceIp };
};

export const auditLogTypes = nconf.get('app:audit_logs:logs_in_transports') ?? ['administration'];
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

export const logS3Debug = {
  debug: (message, detail) => {
    logApp._log('info', message, { detail });
  },
  info: (_message, _detail) => {},
  warn: (_message, _detail) => {},
  error: (_message, _detail) => {}
};

export const logMigration = {
  info: (message) => migrationLogger.log('info', message),
};

export const logApp = {
  _log: (level, message, meta = {}) => {
    if (appLogTransports.length > 0 && appLogger.isLevelEnabled(level)) {
      const data = prepareLogMetadata(meta, { category: LOG_APP, source: 'backend' });
      appLogger.log(level, message, data);
      // Only add in support package starting warn level
      if (appLogger.isLevelEnabled('warn')) {
        supportLogger.log(level, message, data);
      }
    }
  },
  debug: (message, meta = {}) => logApp._log('debug', message, meta),
  info: (message, meta = {}) => logApp._log('info', message, meta),
  warn: (message, meta = {}) => logApp._log('warn', message, meta),
  error: (message, meta = {}) => logApp._log('error', message, meta),
  query: (options, errCallback) => appLogger.query(options, errCallback),
};

export const logAudit = {
  _log: (level, user, operation, meta = {}) => {
    if (auditLogTransports.length > 0) {
      const metaUser = { email: user.user_email, ...user.origin };
      const logMeta = isEmpty(meta) ? { auth: metaUser } : { resource: meta, auth: metaUser };
      const data = prepareLogMetadata(logMeta, { category: LOG_AUDIT, source: 'backend' });
      auditLogger.log(level, operation, data);
    }
  },
  info: (user, operation, meta = {}) => logAudit._log('info', user, operation, meta),
  error: (user, operation, meta = {}) => logAudit._log('error', user, operation, meta),
};

export const logFrontend = {
  _log: (level, message, meta = {}) => {
    const data = prepareLogMetadata(meta, { category: LOG_APP, source: 'frontend' });
    appLogger.log(level, message, data);
    supportLogger.log(level, message, data);
  },
  error: (message, meta = {}) => logFrontend._log('error', message, meta),
};

export const logTelemetry = {
  log: (message) => {
    telemetryLogger.log('info', message);
  }
};

export const PORT = nconf.get('app:port');
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

export const getChatbotUrl = (req) => {
  if (baseUrl && !baseUrl.includes('localhost') && !baseUrl.includes('127.0.0.1')) {
    // Always append base path to the uri
    return baseUrl + basePath;
  }
  if (req) {
    const [hostname, port] = req.headers.host ? req.headers.host.split(':') : [];
    const isCustomPort = port !== '80' && port !== '443';
    const httpPort = isCustomPort && port ? `:${port}` : `:${PORT}`;
    return `${req.protocol}://${hostname}${httpPort}${basePath}`;
  }
  throw UnknownError('Missing request for chatbot');
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

// General
export const ENABLED_API = booleanConf('app:enabled', true);
export const ENABLED_UI = booleanConf('app:enabled_ui', true);

// Playground
export const ENABLED_DEMO_MODE = booleanConf('demo_mode', false);
export const PLAYGROUND_INTROSPECTION_DISABLED = DEV_MODE ? false : (!ENABLED_UI || booleanConf('app:graphql:playground:force_disabled_introspection', true));
export const PLAYGROUND_ENABLED = ENABLED_UI && booleanConf('app:graphql:playground:enabled', true);
export const GRAPHQL_ARMOR_DISABLED = booleanConf('app:graphql:armor_protection:disabled', true);

// Default activated managers
export const ENABLED_TRACING = booleanConf('app:telemetry:tracing:enabled', false);
export const ENABLED_METRICS = booleanConf('app:telemetry:metrics:enabled', false);
export const ENABLED_NOTIFICATION_MANAGER = booleanConf('notification_manager:enabled', true);
export const ENABLED_PUBLISHER_MANAGER = booleanConf('publisher_manager:enabled', true);
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
export const computeAccountStatusChoices = () => {
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

// Feature flags can be enabled in the configuration file
export const ENABLED_FEATURE_FLAGS = nconf.get('app:enabled_dev_features') ?? [];
// a special flag name allows to enable all feature flags at once
export const FEATURE_FLAG_ALL = '*';
export const isFeatureEnabled = (feature) => ENABLED_FEATURE_FLAGS.includes(FEATURE_FLAG_ALL) || ENABLED_FEATURE_FLAGS.includes(feature);

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
    DELETE_TOPIC: `${TOPIC_PREFIX}GROUP_DELETE_TOPIC`,
  },
  [O.ENTITY_TYPE_RULE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}RULE_EDIT_TOPIC`,
  },
  [O.ENTITY_TYPE_ROLE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ROLE_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ROLE_ADDED_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}ROLE_DELETE_TOPIC`,
  },
  [O.ENTITY_TYPE_USER]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}USER_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}USER_ADDED_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}USER_DELETE_TOPIC`,
  },
  [ENTITY_TYPE_WORKSPACE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}WORKSPACE_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}WORKSPACE_ADDED_TOPIC`,
  },
  [O.ENTITY_TYPE_THEME]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}THEME_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}THEME_ADDED_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}THEME_DELETE_TOPIC`,
  },
  [ENTITY_TYPE_PUBLIC_DASHBOARD]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}PUBLIC_DASHBOARD_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}PUBLIC_DASHBOARD_ADDED_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}PUBLIC_DASHBOARD_DELETE_TOPIC`,
  },
  [ENTITY_TYPE_DRAFT_WORKSPACE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}DRAFT_WORKSPACE_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}DRAFT_WORKSPACE_ADDED_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}DRAFT_WORKSPACE_DELETE_TOPIC`,
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
    DELETE_TOPIC: `${TOPIC_PREFIX}MARKING_DEFINITION_EDIT_TOPIC`,
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
  [ENTITY_TYPE_EXCLUSION_LIST]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_EXCLUSION_LIST_EDIT_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_EXCLUSION_LIST_DELETE_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_EXCLUSION_LIST_ADDED_TOPIC`,
  },
  [ENTITY_TYPE_DISSEMINATION_LIST]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_DISSEMINATION_LIST_EDIT_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_DISSEMINATION_LIST_DELETE_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_DISSEMINATION_LIST_ADDED_TOPIC`,
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
  [ENTITY_TYPE_FINTEL_TEMPLATE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}TEMPLATE_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}TEMPLATE_ADDED_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}TEMPLATE_DELETE_TOPIC`,
  },
  [ENTITY_TYPE_PIR]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}PIR_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}PIR_ADDED_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}PIR_DELETE_TOPIC`,
  },
  [ENTITY_TYPE_FINTEL_DESIGN]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}DESIGN_EDIT_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}DESIGN_EDIT_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}DESIGN_EDIT_TOPIC`,
  },
  [ENTITY_TYPE_EMAIL_TEMPLATE]: {
    EDIT_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_EMAIL_TEMPLATE_EDIT_TOPIC`,
    DELETE_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_EMAIL_TEMPLATE_DELETE_TOPIC`,
    ADDED_TOPIC: `${TOPIC_PREFIX}ENTITY_TYPE_EMAIL_TEMPLATE_ADDED_TOPIC`,
  },
};

export const getBusTopicForEntityType = (entityType) => {
  return BUS_TOPICS[entityType];
};

export default nconf;
