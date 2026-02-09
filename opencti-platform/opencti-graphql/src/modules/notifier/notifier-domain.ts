import Ajv from 'ajv';
import { BUS_TOPICS } from '../../config/conf';
import { UnsupportedError } from '../../config/errors';
import { getEntitiesMapFromCache, getEntityFromCache } from '../../database/cache';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { internalFindByIds, fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { isEmptyField } from '../../database/utils';
import type { EditInput, NotifierAddInput, NotifierConnector, NotifierTestInput, QueryNotifiersArgs } from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { internalProcessNotification } from '../../manager/publisherManager';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';
import type { AuthContext, AuthUser } from '../../types/user';
import { MEMBER_ACCESS_RIGHT_VIEW, SYSTEM_USER } from '../../utils/access';
import { now } from '../../utils/format';
import { MOCK_NOTIFICATIONS } from '../../utils/publisher-mock';
import type { BasicStoreEntityTrigger } from '../notification/notification-types';
import {
  BUILTIN_NOTIFIERS_CONNECTORS,
  DEFAULT_TEAM_DIGEST_MESSAGE,
  DEFAULT_TEAM_MESSAGE,
  NOTIFIER_CONNECTOR_EMAIL,
  NOTIFIER_CONNECTOR_UI,
  STATIC_NOTIFIERS,
} from './notifier-statics';
import type { BasicStoreEntityNotifier, StoreEntityNotifier } from './notifier-types';
import { ENTITY_TYPE_NOTIFIER } from './notifier-types';
import { authorizedMembers } from '../../schema/attribute-definition';

const ajv = new Ajv();

const validateNotifier = (notifier: { notifier_connector_id: string; notifier_configuration: string }) => {
  const notifierConnector = BUILTIN_NOTIFIERS_CONNECTORS[notifier.notifier_connector_id];
  if (isEmptyField(notifierConnector) || isEmptyField(notifierConnector.connector_schema)) {
    throw UnsupportedError('Invalid notifier connector', { id: notifier.notifier_connector_id });
  }
  // Connector Schema is valued, we have checked that before
  const validate = ajv.compile(JSON.parse(notifierConnector.connector_schema ?? '{}'));
  const isValidConfiguration = validate(JSON.parse(notifier.notifier_configuration));
  if (!isValidConfiguration) {
    throw UnsupportedError('This configuration is invalid', { configuration: notifier.notifier_configuration, errors: validate.errors });
  }
};

export const addNotifier = async (context: AuthContext, user: AuthUser, notifier: NotifierAddInput): Promise<BasicStoreEntityNotifier> => {
  validateNotifier(notifier);
  const notifierToCreate = { ...notifier, created: now(), updated: now(), authorized_authorities: ['SETTINGS_SETCUSTOMIZATION'] };
  const created = await createEntity(context, user, notifierToCreate, ENTITY_TYPE_NOTIFIER);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates notifier \`${created.name}\` for connector  \`${created.notifier_connector_id}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_NOTIFIER, input: created },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_NOTIFIER].ADDED_TOPIC, created, user);
};

export const notifierGet = (context: AuthContext, user: AuthUser, notifierId: string): BasicStoreEntityNotifier => {
  return storeLoadById(context, user, notifierId, ENTITY_TYPE_NOTIFIER) as unknown as BasicStoreEntityNotifier;
};

export const notifierEdit = async (context: AuthContext, user: AuthUser, notifierId: string, input: EditInput[]) => {
  const fieldsToValidate = {
    notifier_configuration: input.filter((n) => n.key === 'notifier_configuration')[0].value[0] ?? '',
    notifier_connector_id: input.filter((n) => n.key === 'notifier_connector_id')[0].value[0] ?? '',
  };
  validateNotifier(fieldsToValidate);
  const finalInput = input.map(({ key, value }) => {
    const item: { key: string; value: any } = { key, value };
    if (key === authorizedMembers.name) {
      item.value = value.map((id) => ({ id, access_right: MEMBER_ACCESS_RIGHT_VIEW }));
    }
    return item;
  });
  const { element: updatedElem } = await updateAttribute<StoreEntityNotifier>(context, user, notifierId, ENTITY_TYPE_NOTIFIER, finalInput);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for notifier \`${updatedElem.name}\``,
    context_data: { id: notifierId, entity_type: ENTITY_TYPE_NOTIFIER, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_NOTIFIER].EDIT_TOPIC, updatedElem, user);
};

export const notifierDelete = async (context: AuthContext, user: AuthUser, triggerId: string) => {
  const element = await deleteElementById(context, user, triggerId, ENTITY_TYPE_NOTIFIER);
  await notify(BUS_TOPICS[ENTITY_TYPE_NOTIFIER].DELETE_TOPIC, element, user);
  return triggerId;
};

export const notifiersFind = (context: AuthContext, user: AuthUser, opts: QueryNotifiersArgs) => {
  return pageEntitiesConnection<BasicStoreEntityNotifier>(context, user, [ENTITY_TYPE_NOTIFIER], { ...opts, includeAuthorities: true });
};

export const getNotifiers = async (context: AuthContext, user: AuthUser, ids: string[] = []) => {
  const cacheNotifiers = await getEntitiesMapFromCache(context, user, ENTITY_TYPE_NOTIFIER);
  const missingIds = ids.filter((id) => !cacheNotifiers.has(id));
  const notifiers = await internalFindByIds(context, user, missingIds, { type: ENTITY_TYPE_NOTIFIER }) as StoreEntityNotifier[];
  const staticNotifiers = STATIC_NOTIFIERS.filter(({ id }) => missingIds.includes(id));
  return [
    ...(ids.filter((id) => cacheNotifiers.has(id)).map((id) => cacheNotifiers.get(id) as BasicStoreEntityNotifier)),
    ...notifiers,
    ...staticNotifiers,
  ] as BasicStoreEntityNotifier[];
};

export const usableNotifiers = async (context: AuthContext, user: AuthUser) => {
  const notifiers = await fullEntitiesList<BasicStoreEntityNotifier>(context, user, [ENTITY_TYPE_NOTIFIER], { includeAuthorities: true });
  return [...notifiers, ...STATIC_NOTIFIERS].sort((a, b) => {
    if (a.name < b.name) return -1;
    if (a.name > b.name) return 1;
    return 0;
  });
};

export const getNotifierConnector = (context: AuthContext, user: AuthUser, connectorId: string): NotifierConnector | Promise<BasicStoreEntityNotifier> => {
  const builtIn = BUILTIN_NOTIFIERS_CONNECTORS[connectorId];
  if (builtIn) {
    return builtIn;
  }
  if ([NOTIFIER_CONNECTOR_UI, NOTIFIER_CONNECTOR_EMAIL].includes(connectorId)) {
    return { id: connectorId, name: 'Platform' };
  }
  return storeLoadById<BasicStoreEntityNotifier>(context, user, connectorId, ENTITY_TYPE_CONNECTOR);
};

export const initDefaultNotifiers = (context: AuthContext) => {
  return Promise.all([DEFAULT_TEAM_MESSAGE, DEFAULT_TEAM_DIGEST_MESSAGE].map((notifier) => addNotifier(context, SYSTEM_USER, notifier)));
};

export const testNotifier = async (context: AuthContext, user: AuthUser, notifier: NotifierTestInput) => {
  try {
    validateNotifier(notifier);
  } catch (error: any) {
    return error.data ? error.data.reason : error.message;
  }
  const usersFromCache = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const notificationMap = new Map([
    ['default_notification_id', { name: 'test' } as BasicStoreEntityTrigger],
    ['default_notification_id_2', { name: 'test 2' } as BasicStoreEntityTrigger],
    ['default_activity_id', { name: 'test 2' } as BasicStoreEntityTrigger],
  ]);
  return internalProcessNotification(
    context,
    settings,
    notificationMap,
    {
      user_id: user.id,
      user_email: user.user_email,
      user_service_account: user.user_service_account ? user.user_service_account : false,
      notifiers: [],
    },
    notifier,
    MOCK_NOTIFICATIONS[notifier.notifier_test_id],
    [{ created: (new Date()).toISOString() }] as unknown as BasicStoreEntityTrigger[],
    usersFromCache,
  ).catch((error) => {
    return error.message;
  });
};
