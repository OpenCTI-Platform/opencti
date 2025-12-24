import { type BasicStoreEntityIngestionTaxiiCollection, ENTITY_TYPE_INGESTION_TAXII_COLLECTION, type StoreEntityIngestionTaxiiCollection } from './ingestion-types';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { authorizedMembers } from '../../schema/attribute-definition';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import { type EditInput, type IngestionTaxiiCollectionAddInput } from '../../generated/graphql';
import { registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';
import { INGESTION_SETINGESTIONS, MEMBER_ACCESS_RIGHT_VIEW } from '../../utils/access';

export const findById = (context: AuthContext, user: AuthUser, ingestionId: string) => {
  return storeLoadById<BasicStoreEntityIngestionTaxiiCollection>(context, user, ingestionId, ENTITY_TYPE_INGESTION_TAXII_COLLECTION);
};

export const findTaxiiCollectionPaginated = async (context: AuthContext, user: AuthUser, opts = {}) => {
  const args = { ...opts, includeAuthorities: true };
  return pageEntitiesConnection<BasicStoreEntityIngestionTaxiiCollection>(context, user, [ENTITY_TYPE_INGESTION_TAXII_COLLECTION], args);
};

export const addIngestion = async (context: AuthContext, user: AuthUser, input: IngestionTaxiiCollectionAddInput) => {
  const data = { authorized_authorities: [INGESTION_SETINGESTIONS], ...input };
  const { element, isCreation } = await createEntity(context, user, data, ENTITY_TYPE_INGESTION_TAXII_COLLECTION, { complete: true });
  if (isCreation) {
    await registerConnectorForIngestion(context, {
      id: element.id,
      type: 'TAXII-PUSH',
      name: element.name,
      is_running: element.ingestion_running ?? false,
      connector_user_id: input.user_id,
    });
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates taxii collection ingestion \`${input.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION_TAXII_COLLECTION, input },
    });
  }
  return element;
};

export const ingestionEditField = async (context: AuthContext, user: AuthUser, ingestionId: string, input: EditInput[]) => {
  const finalInput = input.map(({ key, value }) => {
    const item = { key, value };
    if (key === authorizedMembers.name) {
      item.value = value.map((id) => ({ id, access_right: MEMBER_ACCESS_RIGHT_VIEW }));
    }
    return item;
  });
  const { element } = await updateAttribute<StoreEntityIngestionTaxiiCollection>(context, user, ingestionId, ENTITY_TYPE_INGESTION_TAXII_COLLECTION, finalInput);
  await registerConnectorForIngestion(context, {
    id: element.id,
    type: 'TAXII-PUSH',
    name: element.name,
    is_running: element.ingestion_running ?? false,
    connector_user_id: element.user_id,
  });

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for taxii collection ingestion \`${element.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_TAXII_COLLECTION, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const ingestionDelete = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  const deleted = await deleteElementById<StoreEntityIngestionTaxiiCollection>(context, user, ingestionId, ENTITY_TYPE_INGESTION_TAXII_COLLECTION);
  await unregisterConnectorForIngestion(context, deleted.id);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes taxii collection ingestion \`${deleted.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_TAXII_COLLECTION, input: deleted },
  });
  return ingestionId;
};
