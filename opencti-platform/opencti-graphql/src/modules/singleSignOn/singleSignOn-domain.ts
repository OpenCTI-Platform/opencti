import type { AuthContext, AuthUser } from '../../types/user';
import { type EditInput, type SingleSignMigrationInput, type SingleSignOnAddInput, StrategyType } from '../../generated/graphql';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntitySingleSignOn, ENTITY_TYPE_SINGLE_SIGN_ON } from './singleSignOn-types';
import { now } from '../../utils/format';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { isSingleSignOnInGuiEnabled } from './singleSignOn';
import nconf from 'nconf';
import { parseSingleSignOnRunConfiguration } from './singleSignOn-migration';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { refreshStrategy, registerStrategy, unregisterStrategy } from './singleSignOn-providers';
import { EnvStrategyType } from '../../config/providers-configuration';

const toEnv = (newStrategyType: StrategyType) => {
  switch (newStrategyType) {
    case StrategyType.LocalStrategy:
      return EnvStrategyType.STRATEGY_LOCAL;
    case StrategyType.SamlStrategy:
      return EnvStrategyType.STRATEGY_SAML;
    case StrategyType.LdapStrategy:
      return EnvStrategyType.STRATEGY_LDAP;
    case StrategyType.OpenIdConnectStrategy:
      return EnvStrategyType.STRATEGY_OPENID;
    case StrategyType.ClientCertStrategy:
      return EnvStrategyType.STRATEGY_CERT;
    case StrategyType.HeaderStrategy:
      return EnvStrategyType.STRATEGY_HEADER;
  }
};

export const isSSOAllowed = async (context: AuthContext) => {
  return isSingleSignOnInGuiEnabled && await isEnterpriseEdition(context);
};

export const checkSSOAllowed = async (context: AuthContext) => {
  if (!isSingleSignOnInGuiEnabled) throw UnsupportedError('Feature not yet available');
  if (!await isEnterpriseEdition(context)) throw UnsupportedError('Enterprise licence is required');
};

// For now it's only a logApp, but will be also send to UI via Redis.
export const logAuthInfo = (message: string, strategyType: EnvStrategyType, meta?: any) => {
  logApp.info(`[Auth][${strategyType}]${message}`, { meta });
};

export const logAuthWarn = (message: string, strategyType: EnvStrategyType, meta?: any) => {
  logApp.warn(`[Auth][${strategyType}]${message}`, { meta });
};

export const logAuthError = (message: string, meta?: any) => {
  logApp.error(`[Auth]${message}`, { meta });
};

export const findSingleSignOnById = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkSSOAllowed(context);
  return storeLoadById<BasicStoreEntitySingleSignOn>(context, user, id, ENTITY_TYPE_SINGLE_SIGN_ON);
};

export const findSingleSignOnPaginated = (context: AuthContext, user: AuthUser, args: any) => {
  if (!isSingleSignOnInGuiEnabled) throw UnsupportedError('Feature not yet available');
  return pageEntitiesConnection<BasicStoreEntitySingleSignOn>(context, user, [ENTITY_TYPE_SINGLE_SIGN_ON], args);
};

// For migration purpose, we need to be able to create an SSO enabled, but not start it immediately
export const internalAddSingleSignOn = async (context: AuthContext, user: AuthUser, input: SingleSignOnAddInput, skipRegister: boolean) => {
  const defaultOps = { created_at: now(), updated_at: now() };
  const singleSignOnInput = { ...input, ...defaultOps };
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
    logAuthInfo('Activating new strategy', toEnv(input.strategy), { identifier: input.identifier });
    await registerStrategy(created);
  }
  return created;
};

export const addSingleSignOn = async (context: AuthContext, user: AuthUser, input: SingleSignOnAddInput) => {
  await checkSSOAllowed(context);
  // Call here the function to check that all mandatory field are in the input
  const created = await internalAddSingleSignOn(context, user, input, false);
  return created;
};

export const fieldPatchSingleSignOn = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  await checkSSOAllowed(context);
  const singleSignOnEntityBeforeUpdate = await findSingleSignOnById(context, user, id);

  if (!singleSignOnEntityBeforeUpdate) {
    throw FunctionalError(`Single sign on ${id} cannot be found`);
  }

  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_SINGLE_SIGN_ON, input);
  const singleSignOnEntityAfterUpdate: BasicStoreEntitySingleSignOn = element;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for Authentication \`${element.strategy}\` - \`${element.identifier}\``,
    context_data: { id, entity_type: ENTITY_TYPE_SINGLE_SIGN_ON, input },
  });

  await refreshStrategy(singleSignOnEntityAfterUpdate); // is it done by cache manager too ??
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const deleteSingleSignOn = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkSSOAllowed(context);
  const singleSignOn = await findSingleSignOnById(context, user, id);

  if (!singleSignOn) {
    throw FunctionalError(`Single sign on ${id} cannot be found`);
  }

  if (singleSignOn.enabled) {
    logAuthInfo('Disabling strategy', toEnv(singleSignOn.strategy), { identifier: singleSignOn.identifier });
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
