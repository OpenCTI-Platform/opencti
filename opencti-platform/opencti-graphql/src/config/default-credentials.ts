import conf, { booleanConf, logApp } from './conf';
import { ConfigurationError } from './errors';

// Known default values, compared in lower case: `changeme` covers ChangeMe, CHANGEME...
const CHANGE_ME = 'changeme';
// The default of app:health_access_key, which keeps /health disabled (same value as DEFAULT_INVALID_CONF_VALUE).
const HEALTH_DISABLED_VALUE = 'ChangeMe';
const RABBITMQ_DEFAULTS = [CHANGE_ME, 'guest'];
const MINIO_DEFAULTS = [CHANGE_ME, 'minioadmin'];
// Remote credentials provider supported by enrichWithRemoteCredentials (credentials.ts), and the MinIO keys its targets replace.
const SUPPORTED_REMOTE_PROVIDER = 'cyberark';
const MINIO_REMOTE_TARGETS: Record<string, string> = { 'minio:access_key': 'accessKeyId', 'minio:secret_key': 'secretAccessKey' };

export const CREDENTIALS_SECURE_BY_DEFAULT = booleanConf('app:credentials:secure_by_default', false);

const isDefaultValue = (value: unknown, defaults: string[]) => {
  return typeof value === 'string' && defaults.includes(value.trim().toLowerCase());
};

// Same lookup as getRemoteCredentialsProviderFields (credentials.ts), not imported to keep this module free of the database layer.
const getMinioRemoteTargets = (): string[] => {
  const provider = conf.get('minio:credentials_provider:selector');
  if (provider !== SUPPORTED_REMOTE_PROVIDER) {
    return [];
  }
  return conf.get(`minio:credentials_provider:${provider}:field_targets`) || conf.get('minio:credentials_provider:field_targets') || [];
};

// The settings still holding a known default value. Only the names are returned, never the values.
export const findDefaultCredentials = (): string[] => {
  const settings: string[] = [];
  const check = (key: string, defaults: string[]) => {
    if (isDefaultValue(conf.get(key), defaults)) {
      settings.push(key);
    }
  };
  // An externally managed admin is locked, so its configured password cannot be used to log in.
  if (!booleanConf('app:admin:externally_managed', false)) {
    check('app:admin:password', [CHANGE_ME]);
  }
  // The exact ChangeMe of the health access key keeps /health disabled, so it is not a credential in use.
  if (conf.get('app:health_access_key') !== HEALTH_DISABLED_VALUE) {
    check('app:health_access_key', [CHANGE_ME]);
  }
  check('rabbitmq:username', RABBITMQ_DEFAULTS);
  check('rabbitmq:password', RABBITMQ_DEFAULTS);
  // The MinIO keys are not used with an AWS role. A remote credentials provider only replaces the keys it targets.
  if (!booleanConf('minio:use_aws_role', false)) {
    const remoteTargets = getMinioRemoteTargets();
    Object.entries(MINIO_REMOTE_TARGETS)
      .filter(([, target]) => !remoteTargets.includes(target))
      .forEach(([key]) => check(key, MINIO_DEFAULTS));
  }
  return settings;
};

export const checkDefaultCredentials = () => {
  const settings = findDefaultCredentials();
  if (settings.length === 0) {
    return;
  }
  if (CREDENTIALS_SECURE_BY_DEFAULT) {
    throw ConfigurationError('Default credentials are configured, change them to start the platform (app:credentials:secure_by_default=true)', { settings });
  }
  logApp.warn('[OPENCTI] Default credentials are configured, change them (app:credentials:secure_by_default=false). '
    + 'The platform will refuse to start with them in an upcoming version: set APP__CREDENTIALS__SECURE_BY_DEFAULT=true to opt in now.', { settings });
};
