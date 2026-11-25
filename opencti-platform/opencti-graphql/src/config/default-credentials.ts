import conf, { booleanConf, logApp } from './conf';
import { getRemoteCredentialsProviderFields, getRemoteCredentialsProviderSelector, isSupportedRemoteCredentialsProvider } from './credentials';
import { ConfigurationError } from './errors';

// Known default values, compared in lower case: `changeme` covers ChangeMe, CHANGEME...
const CHANGE_ME = 'changeme';
// The default of app:health_access_key, which keeps /health disabled (same value as DEFAULT_INVALID_CONF_VALUE).
const HEALTH_DISABLED_VALUE = 'ChangeMe';
const RABBITMQ_DEFAULTS = [CHANGE_ME, 'guest'];
const MINIO_DEFAULTS = [CHANGE_ME, 'minioadmin'];
// The sample defaults of Elasticsearch (elastic/changeme) and OpenSearch (admin/admin), as config/default.json ships none.
// Each user name counts with each default password: elastic/admin or admin/changeme are reported too.
const ELASTICSEARCH_PASSWORD_DEFAULTS = [CHANGE_ME, 'admin'];
const ELASTICSEARCH_USER_DEFAULTS = [CHANGE_ME, 'elastic', 'admin'];
// `default` is the name of the Redis default user.
const REDIS_PASSWORD_DEFAULTS = [CHANGE_ME];
const REDIS_USER_DEFAULTS = [CHANGE_ME, 'default'];
// The configuration keys of a user and password pair, and the fields a remote credentials provider targets to replace them.
type CredentialPair = { userKey: string; passwordKey: string; userField: string; passwordField: string };
const ELASTICSEARCH_PAIR: CredentialPair = {
  userKey: 'elasticsearch:username', passwordKey: 'elasticsearch:password', userField: 'username', passwordField: 'password',
};
const REDIS_PAIR: CredentialPair = { userKey: 'redis:username', passwordKey: 'redis:password', userField: 'username', passwordField: 'password' };
const REDIS_SENTINEL_PAIR: CredentialPair = {
  userKey: 'redis:sentinel_username', passwordKey: 'redis:sentinel_password', userField: 'sentinelUsername', passwordField: 'sentinelPassword',
};
// The MinIO keys, and the fields of the resolved credentials that hold them.
const MINIO_ACCESS_KEY = { key: 'minio:access_key', field: 'accessKeyId' };
const MINIO_SECRET_KEY = { key: 'minio:secret_key', field: 'secretAccessKey' };

export const CREDENTIALS_SECURE_BY_DEFAULT = booleanConf('app:credentials:secure_by_default', false);

const isDefaultValue = (value: unknown, defaults: string[]) => {
  return typeof value === 'string' && defaults.includes(value.trim().toLowerCase());
};

// The default credential is the user and password pair: a default user name only counts with a default password.
const findDefaultPair = (
  user: { key: string; value: unknown },
  password: { key: string; value: unknown },
  passwordDefaults: string[],
  userDefaults = passwordDefaults,
): string[] => {
  if (!isDefaultValue(password.value, passwordDefaults)) {
    return [];
  }
  return isDefaultValue(user.value, userDefaults) ? [user.key, password.key] : [password.key];
};

// The fields a remote credentials provider replaces for a configuration prefix, from the same lookup as enrichWithRemoteCredentials.
const getRemoteTargets = (prefix: string): string[] => {
  const provider = getRemoteCredentialsProviderSelector(prefix);
  if (!isSupportedRemoteCredentialsProvider(provider)) {
    return [];
  }
  return getRemoteCredentialsProviderFields(prefix, provider);
};

const getMinioRemoteTargets = () => getRemoteTargets('minio');

// The fields a remote credentials provider targets are replaced once resolved, so the configured values are not checked.
// The provider falls back to the configured values when it fails: that case is not covered here.
const findConfiguredDefaultPair = (prefix: string, pair: CredentialPair, passwordDefaults: string[], userDefaults: string[]): string[] => {
  const targets = getRemoteTargets(prefix);
  if (targets.includes(pair.passwordField)) {
    return [];
  }
  const userValue = targets.includes(pair.userField) ? undefined : conf.get(pair.userKey);
  return findDefaultPair(
    { key: pair.userKey, value: userValue },
    { key: pair.passwordKey, value: conf.get(pair.passwordKey) },
    passwordDefaults,
    userDefaults,
  );
};

// The user and password written in elasticsearch:url, which the Elasticsearch and OpenSearch clients use over the configured
// or resolved ones: the first URL holding both, as their getAuth.
const getElasticsearchUrlCredentials = (): { username: string; password: string } | undefined => {
  const configured: unknown = conf.get('elasticsearch:url');
  const urls = Array.isArray(configured) ? configured : [configured];
  for (let index = 0; index < urls.length; index += 1) {
    const url = urls[index];
    if (typeof url === 'string' && URL.canParse(url)) {
      const { username, password } = new URL(url);
      if (username !== '' && password !== '') {
        try {
          return { username: decodeURIComponent(username), password: decodeURIComponent(password) };
        } catch {
          // A malformed encoding is refused by the clients themselves
          return undefined;
        }
      }
    }
  }
  return undefined;
};

const findElasticsearchDefaultCredentials = (): string[] => {
  // With AWS SigV4 (opensearch:region), the requests are signed and the user and password are never sent.
  if (conf.get('opensearch:region')) {
    return [];
  }
  // The Elasticsearch clients send the API key instead of the user and password. The OpenSearch client has no API key support:
  // it is only known to be used when forced, as an automatic detection reads the server after this check.
  if (conf.get('elasticsearch:api_key') && conf.get('elasticsearch:engine_client') !== 'opensearch') {
    return [];
  }
  const urlCredentials = getElasticsearchUrlCredentials();
  if (urlCredentials) {
    // The pair is in the URL: name the setting, never its value.
    return isDefaultValue(urlCredentials.password, ELASTICSEARCH_PASSWORD_DEFAULTS) ? ['elasticsearch:url'] : [];
  }
  return findConfiguredDefaultPair('elasticsearch', ELASTICSEARCH_PAIR, ELASTICSEARCH_PASSWORD_DEFAULTS, ELASTICSEARCH_USER_DEFAULTS);
};

const findRedisDefaultCredentials = (): string[] => {
  const settings = findConfiguredDefaultPair('redis', REDIS_PAIR, REDIS_PASSWORD_DEFAULTS, REDIS_USER_DEFAULTS);
  // The Sentinel credentials are only used in Sentinel mode.
  if (conf.get('redis:mode') === 'sentinel') {
    settings.push(...findConfiguredDefaultPair('redis', REDIS_SENTINEL_PAIR, REDIS_PASSWORD_DEFAULTS, REDIS_USER_DEFAULTS));
  }
  return settings;
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
  settings.push(...findElasticsearchDefaultCredentials());
  settings.push(...findRedisDefaultCredentials());
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
