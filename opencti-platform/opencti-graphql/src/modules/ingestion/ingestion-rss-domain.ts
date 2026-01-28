import { type BasicStoreEntityIngestionRss, ENTITY_TYPE_INGESTION_RSS, type StoreEntityIngestionRss } from './ingestion-types';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput, IngestionRssAddInput } from '../../generated/graphql';
import { registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';

export const findById = (context: AuthContext, user: AuthUser, ingestionId: string) => {
  return storeLoadById<BasicStoreEntityIngestionRss>(context, user, ingestionId, ENTITY_TYPE_INGESTION_RSS);
};

export const findRssIngestionPaginated = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return pageEntitiesConnection<BasicStoreEntityIngestionRss>(context, user, [ENTITY_TYPE_INGESTION_RSS], opts);
};

export const findAllRssIngestion = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return fullEntitiesList<BasicStoreEntityIngestionRss>(context, user, [ENTITY_TYPE_INGESTION_RSS], opts);
};

export const addIngestion = async (context: AuthContext, user: AuthUser, input: IngestionRssAddInput) => {
  const { element, isCreation } = await createEntity(context, user, input, ENTITY_TYPE_INGESTION_RSS, { complete: true });
  if (isCreation) {
    await registerConnectorForIngestion(context, {
      id: element.id,
      type: 'RSS',
      name: element.name,
      is_running: element.ingestion_running ?? false,
      connector_user_id: input.user_id,
    });
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates rss ingestion \`${input.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION_RSS, input },
    });
  }
  return element;
};

export const patchRssIngestion = async (context: AuthContext, user: AuthUser, id: string, patch: object) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_INGESTION_RSS, patch);
  return patched.element;
};

export const ingestionEditField = async (context: AuthContext, user: AuthUser, ingestionId: string, input: EditInput[]) => {
  const { element } = await updateAttribute<StoreEntityIngestionRss>(context, user, ingestionId, ENTITY_TYPE_INGESTION_RSS, input);
  await registerConnectorForIngestion(context, {
    id: element.id,
    type: 'RSS',
    name: element.name,
    is_running: element.ingestion_running ?? false,
    connector_user_id: element.user_id,
  });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for rss ingestion \`${element.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_RSS, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const ingestionDelete = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  const deleted = await deleteElementById<StoreEntityIngestionRss>(context, user, ingestionId, ENTITY_TYPE_INGESTION_RSS);
  await unregisterConnectorForIngestion(context, deleted.id);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes rss ingestion \`${deleted.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_RSS, input: deleted },
  });
  return ingestionId;
};
