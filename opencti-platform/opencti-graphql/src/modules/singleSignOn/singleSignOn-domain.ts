import type { AuthContext, AuthUser } from '../../types/user';
import { type EditInput, type SingleSignMigrationInput, type SingleSignOnAddInput, StrategyType } from '../../generated/graphql';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntitySingleSignOn, ENTITY_TYPE_SINGLE_SIGN_ON, type StoreEntitySingleSignOn } from './singleSignOn-types';
import { now } from '../../utils/format';
import { createInternalObject } from '../../domain/internalObject';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { deleteElementById, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { isSingleSignOnInGuiEnabled } from './singleSignOn';
import nconf from 'nconf';
import { parseSingleSignOnRunConfiguration } from './singleSignOn-migration';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';

// For now it's only a logApp, but will be also send to UI via Redis.
export const logAuth = (message: string, strategyType: StrategyType, meta?: any) => {
  logApp.info(`[Auth][${strategyType.toString()}]${message}`, { meta });
};

export const findSingleSignOnById = async (context: AuthContext, user: AuthUser, id: string) => {
  if (!isSingleSignOnInGuiEnabled) throw UnsupportedError('Feature not yet available');
  return storeLoadById<BasicStoreEntitySingleSignOn>(context, user, id, ENTITY_TYPE_SINGLE_SIGN_ON);
};

export const findSingleSignOnPaginated = (context: AuthContext, user: AuthUser, args: any) => {
  if (!isSingleSignOnInGuiEnabled) throw UnsupportedError('Feature not yet available');
  return pageEntitiesConnection<BasicStoreEntitySingleSignOn>(context, user, [ENTITY_TYPE_SINGLE_SIGN_ON], args);
};

export const addSingleSignOn = (context: AuthContext, user: AuthUser, input: SingleSignOnAddInput) => {
  if (!isSingleSignOnInGuiEnabled) throw UnsupportedError('Feature not yet available');
  // Call here the function to check that all mandatory field are in the input
  const defaultOps = { created_at: now(), updated_at: now() };
  const singleSignOnInput = { ...input, ...defaultOps };
  return createInternalObject<StoreEntitySingleSignOn>(context, user, singleSignOnInput, ENTITY_TYPE_SINGLE_SIGN_ON);
};

export const fieldPatchSingleSignOn = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  if (!isSingleSignOnInGuiEnabled) throw UnsupportedError('Feature not yet available');
  const singleSignOn = await findSingleSignOnById(context, user, id);

  if (!singleSignOn) {
    throw FunctionalError(`Single sign on ${id} cannot be found`);
  }

  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_SINGLE_SIGN_ON, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for single sign on \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_SINGLE_SIGN_ON, input },
  });

  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const deleteSingleSignOn = async (context: AuthContext, user: AuthUser, id: string) => {
  if (!isSingleSignOnInGuiEnabled) throw UnsupportedError('Feature not yet available');
  const singleSignOn = await findSingleSignOnById(context, user, id);

  if (!singleSignOn) {
    throw FunctionalError(`Single sign on ${id} cannot be found`);
  }

  const deleted = await deleteElementById(context, user, id, ENTITY_TYPE_SINGLE_SIGN_ON);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes decay exclusion rule \`${deleted.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_SINGLE_SIGN_ON, input: deleted },
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, singleSignOn, user);
  return id;
};

export const runSingleSignOnRunMigration = async (context: AuthContext, user: AuthUser, input: SingleSignMigrationInput) => {
  if (!await isEnterpriseEdition(context)) throw UnsupportedError('Enterprise license is required to run SSO migration');
  logApp.info(`[SSO MIGRATION] dry run ? ${input.dry_run}`);
  const ssoConfigurationEnv = nconf.get('providers');
  return parseSingleSignOnRunConfiguration(context, user, ssoConfigurationEnv, input.dry_run);
};

export const findAllSingleSignOn = (context: AuthContext, user: AuthUser): Promise<BasicStoreEntitySingleSignOn[]> => {
  if (!isSingleSignOnInGuiEnabled) throw UnsupportedError('Feature not yet available');
  return fullEntitiesList(context, user, [ENTITY_TYPE_SINGLE_SIGN_ON]);
};
