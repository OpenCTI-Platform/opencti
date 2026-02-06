import type { AuthContext, AuthUser } from '../../types/user';
import {
  type ConfigurationTypeInput,
  type EditInput,
  EditOperation,
  FilterMode,
  FilterOperator,
  type SingleSignMigrationInput,
  type SingleSignOnAddInput,
  type SingleSignOnSettings,
  StrategyType,
} from '../../generated/graphql';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntitySingleSignOn, ENTITY_TYPE_SINGLE_SIGN_ON } from './singleSignOn-types';
import { now } from '../../utils/format';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import nconf from 'nconf';
import { parseSingleSignOnRunConfiguration } from './singleSignOn-migration';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { unregisterStrategy } from './singleSignOn-providers';
import { EnvStrategyType, getConfigurationAdminEmail, isAuthenticationEditionLocked, isAuthenticationForcedFromEnv } from './providers-configuration';
import { getPlatformCrypto } from '../../utils/platformCrypto';

export const isConfigurationAdminUser = (user: AuthUser): boolean => {
  return user.user_email === getConfigurationAdminEmail();
};

// Encryption region

// Warn: if you change this list, you will need to write a migration on existing SSO entities
export const AUTH_SECRET_LIST = [
  'client_secret', // OpenID
  'bindCredentials', // LDAP
  'privateKey', // SAML
  'decryptionPvk', // SAML
];
export const ENCRYPTED_TYPE = 'encrypted';
const AUTH_DERIVATION_PATH = ['authentication', 'elastic'];
let authenticationKeyPairPromise: any;

const getKeyPair = async () => {
  const factory = await getPlatformCrypto();
  if (!authenticationKeyPairPromise) {
    authenticationKeyPairPromise = factory.deriveAesKey(AUTH_DERIVATION_PATH, 1);
  }
  return await authenticationKeyPairPromise;
};

export const encryptAuthValue = async (value: string) => {
  const keyPair = await getKeyPair();
  const clearDataBuffer = Buffer.from(value);
  const encryptedBuffer = await keyPair.encrypt(clearDataBuffer);
  return encryptedBuffer.toString('base64');
};

export const decryptAuthValue = async (value: string) => {
  const keyPair = await getKeyPair();
  const decodedBuffer = Buffer.from(value, 'base64');
  return await keyPair.decrypt(decodedBuffer);
};

const encryptConfigurationSecrets = async (configurationWithClear: ConfigurationTypeInput[]) => {
  const configurationWithSecrets: ConfigurationTypeInput[] = [];
  if (configurationWithClear) {
    for (let i = 0; i < configurationWithClear?.length; i++) {
      const currentConfig = configurationWithClear[i] as ConfigurationTypeInput;
      if (AUTH_SECRET_LIST.some((key) => key === currentConfig.key) || currentConfig.type === 'secret') {
        const encryptedValue = await encryptAuthValue(currentConfig.value);
        configurationWithSecrets.push({ key: currentConfig.key, value: encryptedValue, type: ENCRYPTED_TYPE });
      } else {
        configurationWithSecrets.push(currentConfig);
      }
    }
  }
  return configurationWithSecrets;
};

// End Encryption region

export const checkAuthenticationEditionLocked = (user: AuthUser) => {
  if (isAuthenticationEditionLocked() && !isConfigurationAdminUser(user)) {
    throw UnsupportedError('Authentication edition is locked by environment variable');
  }
};

export const checkSSOAllowed = async (context: AuthContext) => {
  if (!await isEnterpriseEdition(context)) throw UnsupportedError('Enterprise licence is required');
};

// For now it's only a logApp, but will be also send to UI via Redis.
export const logAuthInfo = (message: string, strategyType: EnvStrategyType | StrategyType, meta?: any) => {
  logApp.info(`[Auth][${strategyType.toUpperCase()}]${message}`, { meta });
};

export const logAuthWarn = (message: string, strategyType: EnvStrategyType | StrategyType, meta?: any) => {
  logApp.warn(`[Auth][${strategyType.toUpperCase()}]${message}`, { meta });
};

export const logAuthError = (message: string, strategyType: EnvStrategyType | StrategyType | undefined, meta?: any) => {
  logApp.error(`[Auth][${strategyType ? strategyType.toUpperCase() : 'Not provided'}]${message}`, { meta });
};

export const findSingleSignOnById = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkSSOAllowed(context);
  return storeLoadById<BasicStoreEntitySingleSignOn>(context, user, id, ENTITY_TYPE_SINGLE_SIGN_ON);
};

export const findSingleSignOnPaginated = async (context: AuthContext, user: AuthUser, args: any) => {
  await checkSSOAllowed(context);
  return pageEntitiesConnection<BasicStoreEntitySingleSignOn>(context, user, [ENTITY_TYPE_SINGLE_SIGN_ON], args);
};

// For migration purpose, we need to be able to create an SSO enabled, but not start it immediately
export const internalAddSingleSignOn = async (context: AuthContext, user: AuthUser, input: SingleSignOnAddInput, skipRegister: boolean) => {
  const defaultOps = { created_at: now(), updated_at: now() };

  if (input.strategy === StrategyType.LocalStrategy) {
    const filters = {
      mode: FilterMode.And,
      filters: [{ key: ['strategy'], values: [StrategyType.LocalStrategy], operator: FilterOperator.Eq }],
      filterGroups: [],
    };
    const hasLocalStrategy = await findSingleSignOnPaginated(context, user, { filters });
    if (hasLocalStrategy.edges.length > 0) {
      throw FunctionalError('Local Strategy already exists in database');
    }
  }
  let configurationWithSecrets: ConfigurationTypeInput[] = [];
  if (input.configuration) {
    configurationWithSecrets = await encryptConfigurationSecrets(input.configuration);
  }

  // Overriding configuration
  const singleSignOnInput = { ...input, ...defaultOps, configuration: configurationWithSecrets };

  const created: BasicStoreEntitySingleSignOn = await createEntity(
    context,
    user,
    singleSignOnInput,
    ENTITY_TYPE_SINGLE_SIGN_ON,
  );
  const ssoId = created.internal_id;

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates Authentication \`${created.strategy}\` - \`${created.identifier}\``,
    context_data: { id: ssoId, entity_type: ENTITY_TYPE_SINGLE_SIGN_ON, input: singleSignOnInput },
  });

  if (created.enabled && !skipRegister) {
    logAuthInfo('Activating new strategy', input.strategy, { identifier: input.identifier });
    await notify(BUS_TOPICS[ENTITY_TYPE_SINGLE_SIGN_ON].EDIT_TOPIC, created, user);
  }
  return created;
};

export const addSingleSignOn = async (context: AuthContext, user: AuthUser, input: SingleSignOnAddInput) => {
  await checkSSOAllowed(context);
  checkAuthenticationEditionLocked(user);
  // Call here the function to check that all mandatory field are in the input
  return await internalAddSingleSignOn(context, user, input, isAuthenticationForcedFromEnv());
};

export const fieldPatchSingleSignOn = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  await checkSSOAllowed(context);
  checkAuthenticationEditionLocked(user);
  const singleSignOnEntityBeforeUpdate = await findSingleSignOnById(context, user, id);

  if (!singleSignOnEntityBeforeUpdate) {
    throw FunctionalError(`Single sign on ${id} cannot be found`);
  }

  const finalInput: EditInput[] = [];
  for (let i = 0; i < input.length; i++) {
    const currentInput = input[i];
    if (currentInput.key === 'configuration') {
      if (!currentInput.operation || currentInput.operation === EditOperation.Add || currentInput.operation === EditOperation.Replace) {
        const configurationEncrypted: ConfigurationTypeInput[] = await encryptConfigurationSecrets(currentInput.value);
        const overrideEditInput: EditInput = {
          ...currentInput,
          value: configurationEncrypted,
        };
        finalInput.push(overrideEditInput);
      }
      finalInput.push(currentInput);
    } else {
      finalInput.push(currentInput);
    }
  }
  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_SINGLE_SIGN_ON, finalInput);
  const singleSignOnEntityAfterUpdate: BasicStoreEntitySingleSignOn = element;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for Authentication \`${element.strategy}\` - \`${element.identifier}\``,
    context_data: { id, entity_type: ENTITY_TYPE_SINGLE_SIGN_ON, input },
  });

  if (!isAuthenticationForcedFromEnv()) {
    await notify(BUS_TOPICS[ENTITY_TYPE_SINGLE_SIGN_ON].EDIT_TOPIC, singleSignOnEntityAfterUpdate, user);
  }

  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const deleteSingleSignOn = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkSSOAllowed(context);
  checkAuthenticationEditionLocked(user);
  const singleSignOn = await findSingleSignOnById(context, user, id);

  if (!singleSignOn) {
    throw FunctionalError(`Single sign on ${id} cannot be found`);
  }

  if (singleSignOn.strategy === StrategyType.LocalStrategy) {
    throw FunctionalError('Cannot delete Local Strategy');
  }

  if (singleSignOn.enabled && !isAuthenticationForcedFromEnv()) {
    logAuthInfo('Disabling strategy', singleSignOn.strategy, { identifier: singleSignOn.identifier });
    await unregisterStrategy(singleSignOn);
  }

  const deleted = await deleteElementById(context, user, id, ENTITY_TYPE_SINGLE_SIGN_ON);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes Authentication \`${deleted.strategy}\` - \`${deleted.identifier}\``,
    context_data: { id, entity_type: ENTITY_TYPE_SINGLE_SIGN_ON, input: deleted },
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, singleSignOn, user);
  return id;
};

export const runSingleSignOnRunMigration = async (context: AuthContext, user: AuthUser, input: SingleSignMigrationInput) => {
  await checkSSOAllowed(context);
  logApp.info(`[SSO MIGRATION] Migration requested with dry_run = ${input.dry_run}`);
  const ssoConfigurationEnv = nconf.get('providers');
  return parseSingleSignOnRunConfiguration(context, user, ssoConfigurationEnv, input.dry_run);
};

export const findAllSingleSignOn = async (context: AuthContext, user: AuthUser): Promise<BasicStoreEntitySingleSignOn[]> => {
  await checkSSOAllowed(context);
  return fullEntitiesList(context, user, [ENTITY_TYPE_SINGLE_SIGN_ON]);
};

export const getAllIdentifiers = async (context: AuthContext, user: AuthUser) => {
  const allSso = await findAllSingleSignOn(context, user);
  return allSso ? allSso.map((sso) => sso.identifier) : [];
};

export const getSingleSignOnSettings = async () => {
  const settings: SingleSignOnSettings = {
    is_force_env: isAuthenticationForcedFromEnv(),
    is_edition_locked: isAuthenticationEditionLocked(),
  };
  return settings;
};
