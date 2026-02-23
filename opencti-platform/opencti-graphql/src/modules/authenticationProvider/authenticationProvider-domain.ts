import type { AuthContext, AuthUser } from '../../types/user';
import {
  type AuthenticationProviderBaseInput,
  AuthenticationProviderType,
  type AvailableSecretInfo,
  ExtraConfEntryType,
  type LdapConfiguration,
  type LdapConfigurationInput,
  type OidcConfiguration,
  type OidcConfigurationInput,
  type SamlConfiguration,
  type SamlConfigurationInput,
  type SecretInfo,
  SecretSource,
} from '../../generated/graphql';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import {
  type BasicStoreEntityAuthenticationProvider,
  ENTITY_TYPE_AUTHENTICATION_PROVIDER,
  type ExtraConfEntry,
  ldapSecretFields,
  oidcSecretFields,
  samlSecretFields,
  type SecretProvider,
} from './authenticationProvider-types';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { createEntity, deleteElementById, patchAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify, redisDeleteAuthLogHistory } from '../../database/redis';
import conf, { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { unregisterStrategy } from './providers';
import { isAuthenticationForcedFromEnv } from './providers-configuration';
import { getPlatformCrypto } from '../../utils/platformCrypto';
import { memoize } from '../../utils/memoize';
import { logAuthInfo } from './providers-logger';
import { isNotEmptyField } from '../../database/utils';
import { enrichWithRemoteCredentials, getRemoteCredentialsProviderSelector } from '../../config/credentials';

// Type for data that are encrypted
const getKeyPair = memoize(async () => {
  const factory = await getPlatformCrypto();
  return factory.deriveAesKey(['authentication', 'elastic'], 1);
});

const encryptAuthValue = async (value: string) => {
  const keyPair = await getKeyPair();
  const clearDataBuffer = Buffer.from(value);
  const encryptedBuffer = await keyPair.encrypt(clearDataBuffer);
  return encryptedBuffer.toString('base64');
};

const decryptAuthValue = async (value: string) => {
  const keyPair = await getKeyPair();
  const decodedBuffer = Buffer.from(value, 'base64');
  return (await keyPair.decrypt(decodedBuffer)).toString();
};

export const buildSecretInfos = (
  type: string,
  configuration: Record<string, unknown>,
): Record<string, SecretInfo> => {
  const secretFields = secretFieldsByType[type as AuthenticationProviderType];
  if (!secretFields) {
    return {};
  }

  const result: Record<string, SecretInfo> = {};
  for (const fieldName of secretFields) {
    const secretName = configuration[`${fieldName}_ref`] as string;
    if (isNotEmptyField(secretName)) {
      result[fieldName] = { source: SecretSource.External, external_secret_name: secretName };
    } else if (isNotEmptyField(configuration[`${fieldName}_encrypted`])) {
      result[fieldName] = { source: SecretSource.Stored };
    } else {
      result[fieldName] = { source: SecretSource.Missing };
    }
  }
  return result;
};

export const getAvailableSecrets = (): AvailableSecretInfo[] => {
  const secrets = conf.get('secrets');
  if (!secrets || typeof secrets !== 'object') {
    return [];
  }
  return Object.keys(secrets).flatMap((name) => {
    const provider = getRemoteCredentialsProviderSelector(`secrets:${name}`);
    if (provider) {
      return { provider_name: provider, secret_name: name };
    }
    if (conf.get(`secrets:${name}:value`)) {
      return { provider_name: 'env', secret_name: name };
    }
    return [];
  });
};

const getSecretValueByName = async (secretName: string, fieldName: string): Promise<string | undefined> => {
  const prefix = `secrets:${secretName}`;
  if (getRemoteCredentialsProviderSelector(prefix)) {
    const enriched = await enrichWithRemoteCredentials(prefix, {});
    return enriched[fieldName];
  }
  return conf.get(`${prefix}:value`);
};

export const retrieveSecrets = async (config: any): Promise<SecretProvider> => {
  const resolve = async (field: string): Promise<string | undefined> => {
    const secretName = config[`${field}_ref`];
    if (isNotEmptyField(secretName)) {
      return getSecretValueByName(secretName, field);
    }
    const encryptedValue = config[`${field}_encrypted`];
    if (isNotEmptyField(encryptedValue)) {
      return decryptAuthValue(encryptedValue);
    }
    return undefined;
  };

  return {
    optional: async (field) => resolve(field),
    mandatory: async (field) => {
      const value = await resolve(field);
      if (!isNotEmptyField(value)) {
        throw FunctionalError('Secret field is missing', { field });
      }
      return value as string;
    },
  };
};

export const secretFieldsByType: Record<AuthenticationProviderType, string[]> = {
  [AuthenticationProviderType.Oidc]: oidcSecretFields,
  [AuthenticationProviderType.Saml]: samlSecretFields,
  [AuthenticationProviderType.Ldap]: ldapSecretFields,
};

const graphQLToStoreConfiguration = async (
  type: AuthenticationProviderType,
  input: Record<string, unknown>,
  existing?: BasicStoreEntityAuthenticationProvider<any>,
) => {
  const secretsFields = secretFieldsByType[type];
  // duplicate input -> remove cleartext values and normalize null/undefined value to undefined
  const output = Object.fromEntries(Object.entries(input)
    .map(([key, value]) => [key, value ?? undefined]));
  output.type = type;
  for await (const fieldName of secretsFields) {
    delete output[fieldName]; // remove cleartext field if provided, it should not be stored
    const encryptedFieldName = `${fieldName}_encrypted`;
    const refFieldName = `${fieldName}_ref`;
    const overrideInput = input[fieldName] as { new_value_cleartext?: string | null; external_secret_name?: string | null } | undefined;
    if (overrideInput) {
      const newValue = overrideInput.new_value_cleartext;
      const secretName = overrideInput.external_secret_name;
      if (secretName !== undefined && secretName !== null && secretName !== '') {
        output[refFieldName] = secretName;
        delete output[encryptedFieldName];
      } else if (newValue !== undefined && newValue !== null && newValue !== '') {
        output[encryptedFieldName] = await encryptAuthValue(newValue);
        delete output[refFieldName];
      } else {
        delete output[encryptedFieldName];
        delete output[refFieldName];
      }
    } else {
      output[encryptedFieldName] = existing?.configuration?.[encryptedFieldName];
      output[refFieldName] = existing?.configuration?.[refFieldName];
    }
  }
  return output;
};

const parseExtraConfValue = (conf: ExtraConfEntry): unknown => {
  if (conf.type === ExtraConfEntryType.Boolean) return conf.value === 'true';
  if (conf.type === ExtraConfEntryType.Number) return Number(conf.value);
  return conf.value;
};

// Multiple entries with the same key are grouped into an array.
// A single entry stays scalar.
export const flatExtraConf = (extraConfInput: ExtraConfEntry[]) => {
  const grouped = new Map<string, unknown[]>();
  for (const conf of extraConfInput) {
    const value = parseExtraConfValue(conf);
    const existing = grouped.get(conf.key);
    if (existing) {
      existing.push(value);
    } else {
      grouped.set(conf.key, [value]);
    }
  }
  const result: Record<string, unknown> = {};
  for (const [key, values] of grouped) {
    result[key] = values.length === 1 ? values[0] : values;
  }
  return result;
};

type ConfigurationInput = OidcConfigurationInput | SamlConfigurationInput | LdapConfigurationInput;

export const checkAuthenticationByEnvVariables = () => {
  if (isAuthenticationForcedFromEnv()) {
    throw UnsupportedError('Authentication is currently managed by env variables');
  }
};

export const findAuthenticationProviderById
  = async <T extends OidcConfiguration | SamlConfiguration | LdapConfiguration | unknown = unknown>(context: AuthContext, user: AuthUser, id: string) => {
    return storeLoadById<BasicStoreEntityAuthenticationProvider<T>>(context, user, id, ENTITY_TYPE_AUTHENTICATION_PROVIDER);
  };

export const findAuthenticationProviderByIdPaginated = async (context: AuthContext, user: AuthUser, args: any) => {
  return pageEntitiesConnection<BasicStoreEntityAuthenticationProvider>(context, user, [ENTITY_TYPE_AUTHENTICATION_PROVIDER], args);
};

export const findAllAuthenticationProvider = async (context: AuthContext, user: AuthUser): Promise<BasicStoreEntityAuthenticationProvider[]> => {
  return fullEntitiesList(context, user, [ENTITY_TYPE_AUTHENTICATION_PROVIDER]);
};

export const getAllIdentifiers = async (context: AuthContext, user: AuthUser) => {
  const allProvider = await findAllAuthenticationProvider(context, user);
  return allProvider.map((provider) => resolveProviderIdentifier(provider));
};

const slugifyName = (name: string): string => {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
};

/**
 * Resolve the identifier that a provider would have from its configuration: use the override if provided, or slugify the name otherwise.
 */
export const resolveProviderIdentifier = (conf: { name: string; identifier_override?: string | null }): string => {
  return conf.identifier_override ?? slugifyName(conf.name);
};

/**
 * Ensure the resolved identifier is not already used by another provider.
 */
const ensureUniqueIdentifier = async (
  context: AuthContext,
  user: AuthUser,
  base: AuthenticationProviderBaseInput,
  excludeId?: string,
) => {
  const newIdentifier = resolveProviderIdentifier(base);
  const allProviders = await findAllAuthenticationProvider(context, user);
  const conflict = allProviders.find((p) => {
    if (excludeId && p.internal_id === excludeId) return false;
    return resolveProviderIdentifier(p) === newIdentifier;
  });
  if (conflict) {
    throw FunctionalError('An authentication provider with the same identifier already exists', {
      identifier: newIdentifier,
      conflicting_provider_id: conflict.internal_id,
      conflicting_provider_name: conflict.name,
    });
  }
};

// For migration purpose, we need to be able to create a provider enabled, but not start it immediately
export const addAuthenticationProvider = async (
  context: AuthContext,
  user: AuthUser,
  { base, configuration }: { base: AuthenticationProviderBaseInput; configuration: ConfigurationInput },
  type: AuthenticationProviderType,
) => {
  checkAuthenticationByEnvVariables();

  // Ensure no other provider resolves to the same identifier
  await ensureUniqueIdentifier(context, user, base);

  // Create the store object
  const input = { ...base, type, configuration: await graphQLToStoreConfiguration(type, configuration) };

  const created: BasicStoreEntityAuthenticationProvider = await createEntity(
    context,
    user,
    input,
    ENTITY_TYPE_AUTHENTICATION_PROVIDER,
  );
  const providerId = created.internal_id;
  const identifier = resolveProviderIdentifier(created);

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates Authentication \`${created.type}\` - \`${identifier}\``,
    context_data: {
      id: providerId,
      entity_type: ENTITY_TYPE_AUTHENTICATION_PROVIDER,
      input,
    },
  });

  if (created.enabled) {
    logAuthInfo('Activating new provider', type, { identifier });
    await notify(BUS_TOPICS[ENTITY_TYPE_AUTHENTICATION_PROVIDER].EDIT_TOPIC, created, user);
  }
  return created;
};

export const editAuthenticationProvider = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  { base, configuration }: { base: AuthenticationProviderBaseInput; configuration: ConfigurationInput },
  type: AuthenticationProviderType,
) => {
  checkAuthenticationByEnvVariables();
  const existing = await findAuthenticationProviderById(context, user, id);
  if (!existing) {
    throw FunctionalError('Authentication provider cannot be found', { id });
  }
  if (existing.type !== type) {
    throw FunctionalError('Cannot update authentication provider, invalid type provided', {
      id,
      providerType: existing.type,
      expectedType: type,
    });
  }

  // Ensure the new identifier does not conflict with another provider (exclude self)
  await ensureUniqueIdentifier(context, user, base, id);

  // Create the store object
  const input = { ...base, type, configuration: await graphQLToStoreConfiguration(type, configuration, existing) };

  const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_AUTHENTICATION_PROVIDER, input);

  const identifier = resolveProviderIdentifier(element as unknown as BasicStoreEntityAuthenticationProvider);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates Authentication \`${type}\` - \`${identifier}\``,
    context_data: { id, entity_type: ENTITY_TYPE_AUTHENTICATION_PROVIDER, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_AUTHENTICATION_PROVIDER].EDIT_TOPIC, element, user);
};

export const deleteAuthenticationProvider = async (context: AuthContext, user: AuthUser, id: string, type: AuthenticationProviderType) => {
  checkAuthenticationByEnvVariables();
  const provider = await findAuthenticationProviderById(context, user, id);
  if (!provider) {
    throw FunctionalError('Authentication provider cannot be found', { id });
  }
  if (provider.type !== type) {
    throw FunctionalError('Cannot delete authentication provider, invalid type provided', {
      id,
      providerType: provider.type,
      expectedType: type,
    });
  }

  if (provider.enabled) {
    logAuthInfo('Disabling strategy', provider.type, { name: provider.name });
    await unregisterStrategy(provider);
  }

  await redisDeleteAuthLogHistory(provider.internal_id);
  const deleted = await deleteElementById(context, user, id, ENTITY_TYPE_AUTHENTICATION_PROVIDER) as unknown as BasicStoreEntityAuthenticationProvider;
  const deletedIdentifier = resolveProviderIdentifier(deleted);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes Authentication \`${deleted.type}\` - \`${deletedIdentifier}\``,
    context_data: { id, entity_type: ENTITY_TYPE_AUTHENTICATION_PROVIDER, input: deleted },
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, provider, user);
  return id;
};
