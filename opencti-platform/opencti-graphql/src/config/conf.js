import { lstatSync, readFileSync } from 'fs';
import nconf from 'nconf';
import Etcd from 'nconf-etcd2';
import * as R from 'ramda';
import { isEmpty } from 'ramda';
import winston, { format } from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'path';
import * as O from '../schema/internalObject';
import * as M from '../schema/stixMetaObject';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
  ABSTRACT_STIX_DOMAIN_OBJECT,
} from '../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';

const pjson = require('../../package.json');

// https://golang.org/src/crypto/x509/root_linux.go
const LINUX_CERTFILES = [
  '/etc/ssl/certs/ca-certificates.crt', // Debian/Ubuntu/Gentoo etc.
  '/etc/pki/tls/certs/ca-bundle.crt', // Fedora/RHEL 6
  '/etc/ssl/ca-bundle.pem', // OpenSUSE
  '/etc/pki/tls/cacert.pem', // OpenELEC
  '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', // CentOS/RHEL 7
  '/etc/ssl/certs/ca.crt', // MacOS
  '/etc/ssl/cert.pem',
];

const DEFAULT_ENV = 'production';
export const OPENCTI_SESSION = 'opencti_session';
export const OPENCTI_WEB_TOKEN = 'Default';
export const OPENCTI_ISSUER = 'OpenCTI';
export const OPENCTI_DEFAULT_DURATION = 'P99Y';
export const BUS_TOPICS = {
  [O.ENTITY_TYPE_SETTINGS]: {
    EDIT_TOPIC: 'SETTINGS_EDIT_TOPIC',
    ADDED_TOPIC: 'SETTINGS_ADDED_TOPIC',
  },
  [O.ENTITY_TYPE_ATTRIBUTE]: {
    EDIT_TOPIC: 'ATTRIBUTE_EDIT_TOPIC',
    ADDED_TOPIC: 'ATTRIBUTE_ADDED_TOPIC',
  },
  [O.ENTITY_TYPE_GROUP]: {
    EDIT_TOPIC: 'GROUP_EDIT_TOPIC',
    ADDED_TOPIC: 'GROUP_ADDED_TOPIC',
  },
  [O.ENTITY_TYPE_ROLE]: {
    EDIT_TOPIC: 'ROLE_EDIT_TOPIC',
    ADDED_TOPIC: 'ROLE_ADDED_TOPIC',
  },
  [O.ENTITY_TYPE_USER]: {
    EDIT_TOPIC: 'USER_EDIT_TOPIC',
    ADDED_TOPIC: 'USER_ADDED_TOPIC',
  },
  [O.ENTITY_TYPE_WORKSPACE]: {
    EDIT_TOPIC: 'WORKSPACE_EDIT_TOPIC',
    ADDED_TOPIC: 'WORKSPACE_ADDED_TOPIC',
  },
  [M.ENTITY_TYPE_LABEL]: {
    EDIT_TOPIC: 'LABEL_EDIT_TOPIC',
    ADDED_TOPIC: 'LABEL_ADDED_TOPIC',
  },
  [O.ENTITY_TYPE_CONNECTOR]: {
    EDIT_TOPIC: 'CONNECTOR_EDIT_TOPIC',
  },
  [O.ENTITY_TYPE_TAXII_COLLECTION]: {
    EDIT_TOPIC: 'TAXII_COLLECTION_EDIT_TOPIC',
    ADDED_TOPIC: 'TAXII_COLLECTION_ADDED_TOPIC',
  },
  [O.ENTITY_TYPE_STREAM_COLLECTION]: {
    EDIT_TOPIC: 'STREAM_COLLECTION_EDIT_TOPIC',
    ADDED_TOPIC: 'STREAM_COLLECTION_ADDED_TOPIC',
  },
  [O.ENTITY_TYPE_SYNC]: {
    EDIT_TOPIC: 'SYNC_EDIT_TOPIC',
    ADDED_TOPIC: 'SYNC_ADDED_TOPIC',
  },
  [O.ENTITY_TYPE_USER_SUBSCRIPTION]: {
    EDIT_TOPIC: 'USER_SUBSCRIPTION_EDIT_TOPIC',
    ADDED_TOPIC: 'USER_SUBSCRIPTION_ADDED_TOPIC',
  },
  [M.ENTITY_TYPE_MARKING_DEFINITION]: {
    EDIT_TOPIC: 'MARKING_DEFINITION_EDIT_TOPIC',
    ADDED_TOPIC: 'MARKING_DEFINITION_ADDED_TOPIC',
  },
  [M.ENTITY_TYPE_LABEL]: {
    EDIT_TOPIC: 'LABEL_EDIT_TOPIC',
    ADDED_TOPIC: 'LABEL_ADDED_TOPIC',
  },
  [M.ENTITY_TYPE_EXTERNAL_REFERENCE]: {
    EDIT_TOPIC: 'EXTERNAL_REFERENCE_EDIT_TOPIC',
    ADDED_TOPIC: 'EXTERNAL_REFERENCE_ADDED_TOPIC',
  },
  [M.ENTITY_TYPE_KILL_CHAIN_PHASE]: {
    EDIT_TOPIC: 'KILL_CHAIN_PHASE_EDIT_TOPIC',
    ADDED_TOPIC: 'KILL_CHAIN_PHASE_ADDED_TOPIC',
  },
  [ABSTRACT_STIX_CORE_OBJECT]: {
    EDIT_TOPIC: 'STIX_CORE_OBJECT_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_CORE_OBJECT_ADDED_TOPIC',
  },
  [ABSTRACT_STIX_DOMAIN_OBJECT]: {
    EDIT_TOPIC: 'STIX_DOMAIN_OBJECT_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_DOMAIN_OBJECT_ADDED_TOPIC',
  },
  [ABSTRACT_STIX_CYBER_OBSERVABLE]: {
    EDIT_TOPIC: 'STIX_CYBER_OBSERVABLE_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_CYBER_OBSERVABLE_ADDED_TOPIC',
  },
  [ABSTRACT_STIX_CORE_RELATIONSHIP]: {
    EDIT_TOPIC: 'STIX_CORE_RELATIONSHIP_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_CORE_RELATIONSHIP_ADDED_TOPIC',
  },
  [STIX_SIGHTING_RELATIONSHIP]: {
    EDIT_TOPIC: 'STIX_SIGHTING_RELATIONSHIP_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_SIGHTING_RELATIONSHIP_ADDED_TOPIC',
  },
  [ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP]: {
    EDIT_TOPIC: 'STIX_CYBER_OBSERVABLE_RELATIONSHIP_EDIT_TOPIC',
    ADDED_TOPIC: 'STIX_CYBER_OBSERVABLE_RELATIONSHIP_ADDED_TOPIC',
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

const etcdHosts = process.env.OPENCTI_ETCD_HOSTS || 'https://etcd.aws.darklight.ai:2379';
if (process.env.OPENCTI_ETCD_CA_CRT) {
  let etcdCaCert = process.env.OPENCTI_ETCD_CA_CRT;
  if (etcdCaCert === undefined || etcdCaCert === null ) {
    for (const cert of LINUX_CERTFILES) {
      try {
        if (lstatSync(cert).isFile()) {
          etcdCaCert = cert;
          break;
        }
      } catch (err) {
        if (err.code === 'ENOENT') {
          // eslint-disable-next-line no-continue
          continue;
        } else {
          throw err;
        }
      }
    }
  }

  var etcdOptions = {
    ca: readFileSync(etcdCaCert)
  };
  try {
  const provEtcd = nconf.use('etcd', { namespace: 'system', hosts: [etcdHosts], etcd: etcdOptions});
  } catch(e) {
    console.error(e);
    throw e;
  }
}

// START TEST CODE
// var etcdValue = nconf.get('foo:bar');
// console.log("ETCD TEST VALUE: " + etcdValue)
// var jsonValue = nconf.get('fizz:buzz');
// console.log("JSON TEST VALUE: " + jsonValue)
// nconf.set('fizz:buzz', Math.floor((Math.random() * (100))));
// END TEST CODE

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
const addBasicMetaInformation = (category, meta) => ({ ...meta, category, version: PLATFORM_VERSION });
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

// const AppBasePath = nconf.get('app:base_path').trim();
// const contextPath = isEmpty(AppBasePath) || AppBasePath === '/' ? '' : AppBasePath;
// export const basePath = isEmpty(AppBasePath) || contextPath.startsWith('/') ? contextPath : `/${contextPath}`;

const BasePathConfig = nconf.get('app:base_path')?.trim() ?? '';
const AppBasePath = BasePathConfig.endsWith('/') ? BasePathConfig.slice(0, -1) : BasePathConfig;
export const basePath = isEmpty(AppBasePath) || AppBasePath.startsWith('/') ? AppBasePath : `/${AppBasePath}`;

export const configureCA = (certificates) => {
  if (certificates.length) {
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
        // eslint-disable-next-line no-continue
        continue;
      } else {
        throw err;
      }
    }
  }
  return { ca: [] };
};

// Expose global configuration
export const ENABLED_API = booleanConf('app:enabled', true);
export const ENABLED_EXPIRED_MANAGER = booleanConf('expiration_scheduler:enabled', false);
export const ENABLED_TASK_SCHEDULER = booleanConf('task_scheduler:enabled', false);
export const ENABLED_SYNC_MANAGER = booleanConf('sync_manager:enabled', false);
export const ENABLED_RULE_ENGINE = booleanConf('rule_engine:enabled', false);
export const ENABLED_SUBSCRIPTION_MANAGER = booleanConf('subscription_scheduler:enabled', false);
export const ENABLED_CACHING = booleanConf('redis:use_as_cache', false);

export default nconf;
