import conf, { booleanConf, logApp } from './conf';
import { ConfigurationError } from './errors';

// Known default values, compared in lower case: `changeme` covers ChangeMe, CHANGEME...
const CHANGE_ME = 'changeme';
// The default of app:health_access_key, which keeps /health disabled (same value as DEFAULT_INVALID_CONF_VALUE).
const HEALTH_DISABLED_VALUE = 'ChangeMe';
const RABBITMQ_DEFAULTS = [CHANGE_ME, 'guest'];
const MINIO_DEFAULTS = [CHANGE_ME, 'minioadmin'];
// Remote credentials provider supported by enrichWithRemoteCredentials (credentials.ts).
const SUPPORTED_REMOTE_PROVIDER = 'cyberark';
// The MinIO keys, and the fields of the resolved credentials that hold them.
const MINIO_ACCESS_KEY = { key: 'minio:access_key', field: 'accessKeyId' };
const MINIO_SECRET_KEY = { key: 'minio:secret_key', field: 'secretAccessKey' };

export const CREDENTIALS_SECURE_BY_DEFAULT = booleanConf('app:credentials:secure_by_default', false);

const isDefaultValue = (value: unknown, defaults: string[]) => {
  return typeof value === 'string' && defaults.includes(value.trim().toLowerCase());
};

// The default credential is the user and password pair: a default user name only counts with a default password.
const findDefaultPair = (user: { key: string; value: unknown }, password: { key: string; value: unknown }, defaults: string[]): string[] => {
  if (!isDefaultValue(password.value, defaults)) {
    return [];
  }
  return isDefaultValue(user.value, defaults) ? [user.key, password.key] : [password.key];
};

// Same lookup as getRemoteCredentialsProviderFields (credentials.ts), not imported to keep this module free of the database layer.
const getMinioRemoteTargets = (): string[] => {
  const provider = conf.get('minio:credentials_provider:selector');
  if (provider !== SUPPORTED_REMOTE_PROVIDER) {
    return [];
  }
  return conf.get(`minio:credentials_provider:${provider}:field_targets`) || conf.get('minio:credentials_provider:field_targets') || [];
};

const findMinioDefaultPair = (accessKey: unknown, secretKey: unknown) => {
  return findDefaultPair({ key: MINIO_ACCESS_KEY.key, value: accessKey }, { key: MINIO_SECRET_KEY.key, value: secretKey }, MINIO_DEFAULTS);
};

// The settings still holding a known default value. Only the names are returned, never the values.
export const findDefaultCredentials = (): string[] => {
  const settings: string[] = [];
  // An externally managed admin is locked, so its configured password cannot be used to log in.
  // Same strict test as initAdmin (user-domain.ts), which locks the admin only on a true boolean.
  if (conf.get('app:admin:externally_managed') !== true && isDefaultValue(conf.get('app:admin:password'), [CHANGE_ME])) {
    settings.push('app:admin:password');
  }
  // The exact ChangeMe of the health access key keeps /health disabled, so it is not a credential in use.
  const healthAccessKey = conf.get('app:health_access_key');
  if (healthAccessKey !== HEALTH_DISABLED_VALUE && isDefaultValue(healthAccessKey, [CHANGE_ME])) {
    settings.push('app:health_access_key');
  }
  settings.push(...findDefaultPair(
    { key: 'rabbitmq:username', value: conf.get('rabbitmq:username') },
    { key: 'rabbitmq:password', value: conf.get('rabbitmq:password') },
    RABBITMQ_DEFAULTS,
  ));
  // The MinIO keys are not used with an AWS role. With a remote credentials provider, they are checked once resolved.
  if (!booleanConf('minio:use_aws_role', false) && getMinioRemoteTargets().length === 0) {
    settings.push(...findMinioDefaultPair(conf.get(MINIO_ACCESS_KEY.key), conf.get(MINIO_SECRET_KEY.key)));
  }
  return settings;
};

// The MinIO keys still holding a known default once resolved by a remote credentials provider.
// The provider falls back to the configured keys when it fails, so the startup check cannot vouch for them.
export const findResolvedMinioDefaultCredentials = (resolved: Record<string, unknown>): string[] => {
  if (getMinioRemoteTargets().length === 0) {
    return [];
  }
  return findMinioDefaultPair(resolved[MINIO_ACCESS_KEY.field], resolved[MINIO_SECRET_KEY.field]);
};

const reportDefaultCredentials = (settings: string[], problem: string) => {
  if (settings.length === 0) {
    return;
  }
  if (CREDENTIALS_SECURE_BY_DEFAULT) {
    throw ConfigurationError(`${problem} to start the platform (app:credentials:secure_by_default=true)`, { settings });
  }
  logApp.warn(`[OPENCTI] ${problem} (app:credentials:secure_by_default=false). `
    + 'The platform will refuse to start with them in an upcoming version: set APP__CREDENTIALS__SECURE_BY_DEFAULT=true to opt in now.', { settings });
};

export const checkDefaultCredentials = () => {
  reportDefaultCredentials(findDefaultCredentials(), 'Default credentials are configured, change them');
};

export const checkResolvedMinioCredentials = (resolved: Record<string, unknown>) => {
  reportDefaultCredentials(
    findResolvedMinioDefaultCredentials(resolved),
    'Default MinIO keys are in use with the remote credentials provider, which returned them or failed and fell back to the configured keys: '
    + 'check the provider and the configured keys',
  );
};
