import type { AuthContext, AuthUser } from '../../types/user';
import {
  type AuthenticationProviderBaseInput,
  type AuthenticationProviderMigrationInput,
  type AuthenticationProviderSettings,
  AuthenticationProviderType,
  ExtraConfEntryType,
  type LdapConfiguration,
  type LdapConfigurationInput,
  type OidcConfiguration,
  type OidcConfigurationInput,
  type SamlConfiguration,
  type SamlConfigurationInput,
} from '../../generated/graphql';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import {
  type BasicStoreEntityAuthenticationProvider,
  ENTITY_TYPE_AUTHENTICATION_PROVIDER,
  oidcSecretFields,
  samlSecretFields,
  ldapSecretFields,
  type ExtraConfEntry,
} from './authenticationProvider-types';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { createEntity, deleteElementById, patchAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import nconf from 'nconf';
import { parseAuthenticationProviderConfiguration } from './authenticationProvider-migration';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { unregisterStrategy } from './providers';
import { getConfigurationAdminEmail, isAuthenticationEditionLocked, isAuthenticationForcedFromEnv } from './providers-configuration';
import { getPlatformCrypto } from '../../utils/platformCrypto';
import { memoize } from '../../utils/memoize';
import { logAuthInfo } from './providers-logger';
import { isNotEmptyField } from '../../database/utils';

export const isConfigurationAdminUser = (user: AuthUser): boolean => {
  return user.user_email === getConfigurationAdminEmail();
};

// Type for data that are encrypted
const getKeyPair = memoize(async () => {
  const factory = await getPlatformCrypto();
  return factory.deriveAesKey(['authentication', 'elastic'], 1);
});

export const encryptAuthValue = async (value: string) => {
  const keyPair = await getKeyPair();
  const clearDataBuffer = Buffer.from(value);
  const encryptedBuffer = await keyPair.encrypt(clearDataBuffer);
  return encryptedBuffer.toString('base64');
};

export const decryptAuthValue = async (value: string) => {
  const keyPair = await getKeyPair();
  const decodedBuffer = Buffer.from(value, 'base64');
  return (await keyPair.decrypt(decodedBuffer)).toString();
};

export const secretFieldsByType = {
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
  // duplicate input -> encrypt cleartext values and normalize null/undefined value to undefined
  const output = Object.fromEntries(Object.entries(input)
    .map(([key, value]) => [key, value ?? undefined]));
  output.type = type;
  // Handle secrets fields
  for await (const fieldName of secretsFields) {
    const clearTextFieldName = `${fieldName}_cleartext`;
    const inputClearTextValue = input[clearTextFieldName] as string | undefined;
    const previousEncryptedValue = existing?.configuration?.[`${fieldName}_encrypted`] as string | undefined;
    const encryptedValue = inputClearTextValue && isNotEmptyField(inputClearTextValue)
      ? await encryptAuthValue(inputClearTextValue) : previousEncryptedValue;
    if (!encryptedValue) {
      throw FunctionalError('Secret field must be provided', { field: fieldName });
    }
    // Replace cleartext field by encrypted field
    delete output[clearTextFieldName];
    output[`${fieldName}_encrypted`] = encryptedValue;
  }
  return output;
};

export const flatExtraConf = (extraConfInput: ExtraConfEntry[]) => extraConfInput.reduce((acc, conf) => {
  let value;
  if (conf.type === ExtraConfEntryType.Boolean) {
    value = conf.value === 'true';
  } else if (conf.type === ExtraConfEntryType.Number) {
    value = Number(conf.value);
  } else {
    value = conf.value;
  }
  return ({ ...acc, [conf.key]: value });
}, {});

type ConfigurationInput = OidcConfigurationInput | SamlConfigurationInput | LdapConfigurationInput;

export const checkAuthenticationEditionLocked = (user: AuthUser) => {
  if (isAuthenticationEditionLocked() && !isConfigurationAdminUser(user)) {
    throw UnsupportedError('Authentication edition is locked by environment variable');
  }
};

export const checkAllowed = async (context: AuthContext) => {
  if (!await isEnterpriseEdition(context)) throw UnsupportedError('Enterprise licence is required');
};

export const findAuthenticationProviderById
  = async <T extends OidcConfiguration | SamlConfiguration | LdapConfiguration | unknown = unknown>(context: AuthContext, user: AuthUser, id: string) => {
    await checkAllowed(context);
    return storeLoadById<BasicStoreEntityAuthenticationProvider<T>>(context, user, id, ENTITY_TYPE_AUTHENTICATION_PROVIDER);
  };

export const findAuthenticationProviderByIdPaginated = async (context: AuthContext, user: AuthUser, args: any) => {
  await checkAllowed(context);
  return pageEntitiesConnection<BasicStoreEntityAuthenticationProvider>(context, user, [ENTITY_TYPE_AUTHENTICATION_PROVIDER], args);
};

export const findAllAuthenticationProvider = async (context: AuthContext, user: AuthUser): Promise<BasicStoreEntityAuthenticationProvider[]> => {
  await checkAllowed(context);
  return fullEntitiesList(context, user, [ENTITY_TYPE_AUTHENTICATION_PROVIDER]);
};

export const getAllIdentifiers = async (context: AuthContext, user: AuthUser) => {
  const allProvider = await findAllAuthenticationProvider(context, user);
  return allProvider.map((provider) => provider.identifier_override ?? provider.id);
};

// For migration purpose, we need to be able to create a provider enabled, but not start it immediately
export const addAuthenticationProvider = async (
  context: AuthContext,
  user: AuthUser,
  { base, configuration }: { base: AuthenticationProviderBaseInput; configuration: ConfigurationInput },
  type: AuthenticationProviderType,
  skipRegisterParam?: boolean,
) => {
  await checkAllowed(context);
  checkAuthenticationEditionLocked(user);

  const skipRegister = skipRegisterParam ?? isAuthenticationForcedFromEnv();

  // Create the store object
  const input = { ...base, type, configuration: await graphQLToStoreConfiguration(type, configuration) };

  const created: BasicStoreEntityAuthenticationProvider = await createEntity(
    context,
    user,
    input,
    ENTITY_TYPE_AUTHENTICATION_PROVIDER,
  );
  const providerId = created.internal_id;
  const identifier = created.identifier_override ?? providerId;

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

  if (created.enabled && !skipRegister) {
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
  await checkAllowed(context);
  checkAuthenticationEditionLocked(user);
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

  // Create the store object
  const input = { ...base, type, configuration: await graphQLToStoreConfiguration(type, configuration, existing) };

  const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_AUTHENTICATION_PROVIDER, input);

  const providerId = element.internal_id;
  const identifier = element.identifier_override ?? providerId;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates Authentication \`${type}\` - \`${identifier}\``,
    context_data: { id, entity_type: ENTITY_TYPE_AUTHENTICATION_PROVIDER, input },
  });

  if (!isAuthenticationForcedFromEnv()) {
    await notify(BUS_TOPICS[ENTITY_TYPE_AUTHENTICATION_PROVIDER].EDIT_TOPIC, element, user);
  }

  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const deleteAuthenticationProvider = async (context: AuthContext, user: AuthUser, id: string, type: AuthenticationProviderType) => {
  await checkAllowed(context);
  checkAuthenticationEditionLocked(user);
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

  if (provider.enabled && !isAuthenticationForcedFromEnv()) {
    logAuthInfo('Disabling strategy', provider.type, { name: provider.name });
    await unregisterStrategy(provider);
  }

  const deleted = await deleteElementById(context, user, id, ENTITY_TYPE_AUTHENTICATION_PROVIDER);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes Authentication \`${deleted.strategy}\` - \`${deleted.identifier}\``,
    context_data: { id, entity_type: ENTITY_TYPE_AUTHENTICATION_PROVIDER, input: deleted },
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, provider, user);
  return id;
};

export const runAuthenticationProviderMigration = async (context: AuthContext, user: AuthUser, input: AuthenticationProviderMigrationInput) => {
  await checkAllowed(context);
  logApp.info(`[AUTH PROVIDER MIGRATION] Migration requested with dry_run = ${input.dry_run}`);
  const providerConfigurationEnv = nconf.get('providers');
  return parseAuthenticationProviderConfiguration(context, user, providerConfigurationEnv, input.dry_run);
};

export const getAuthenticationProviderSettings = async () => {
  const settings: AuthenticationProviderSettings = {
    is_force_env: isAuthenticationForcedFromEnv(),
    is_edition_locked: isAuthenticationEditionLocked(),
  };
  return settings;
};
