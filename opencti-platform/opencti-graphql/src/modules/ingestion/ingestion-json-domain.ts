import type { AuthContext, AuthUser } from '../../types/user';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityIngestionJson, ENTITY_TYPE_INGESTION_JSON } from './ingestion-types';
import { verifyIngestionAuthenticationContent } from './ingestion-common';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';
import { publishUserAction } from '../../listener/UserActionListener';
import { type BasicStoreEntityJsonMapper, ENTITY_TYPE_JSON_MAPPER } from '../internal/jsonMapper/jsonMapper-types';
import type { EditInput, IngestionJsonAddInput, JsonMapperTestResult } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { StixObject } from '../../types/stix-common';

export const findById = (context: AuthContext, user: AuthUser, ingestionId: string) => {
  return storeLoadById<BasicStoreEntityIngestionJson>(context, user, ingestionId, ENTITY_TYPE_INGESTION_JSON);
};

export const findAllPaginated = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return listEntitiesPaginated<BasicStoreEntityIngestionJson>(context, user, [ENTITY_TYPE_INGESTION_JSON], opts);
};

export const findAllJsonIngestions = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return listAllEntities<BasicStoreEntityIngestionJson>(context, user, [ENTITY_TYPE_INGESTION_JSON], opts);
};

export const findJsonMapperForIngestionById = (context: AuthContext, user: AuthUser, jsonMapperId: string) => {
  return storeLoadById<BasicStoreEntityJsonMapper>(context, user, jsonMapperId, ENTITY_TYPE_JSON_MAPPER);
};

export const deleteIngestionJson = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  const deleted = await deleteElementById(context, user, ingestionId, ENTITY_TYPE_INGESTION_JSON);
  await unregisterConnectorForIngestion(context, deleted.id);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes json ingestion \`${deleted.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_JSON, input: deleted }
  });
  return ingestionId;
};

export const addIngestionJson = async (context: AuthContext, user: AuthUser, input: IngestionJsonAddInput) => {
  if (input.authentication_value) {
    verifyIngestionAuthenticationContent(input.authentication_type, input.authentication_value);
  }
  const { element, isCreation } = await createEntity(context, user, input, ENTITY_TYPE_INGESTION_JSON, { complete: true });
  if (isCreation) {
    await registerConnectorForIngestion(context, {
      id: element.id,
      type: 'JSON',
      name: element.name,
      is_running: element.ingestion_running ?? false,
      connector_user_id: input.user_id
    });
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates json ingestion \`${input.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION_JSON, input }
    });
  }
  return element;
};

export const ingestionJsonEditField = async (context: AuthContext, user: AuthUser, ingestionId: string, input: EditInput[]) => {
  if (input.some(((editInput) => editInput.key === 'authentication_value'))) {
    const ingestionConfiguration = await findById(context, user, ingestionId);
    const authenticationValueField = input.find(((editInput) => editInput.key === 'authentication_value'));
    if (authenticationValueField && authenticationValueField.value[0]) {
      verifyIngestionAuthenticationContent(ingestionConfiguration.authentication_type, authenticationValueField.value[0]);
    }
  }

  const { element } = await updateAttribute(context, user, ingestionId, ENTITY_TYPE_INGESTION_JSON, input);
  await registerConnectorForIngestion(context, {
    id: element.id,
    type: 'JSON',
    name: element.name,
    is_running: element.ingestion_running ?? false,
    connector_user_id: element.user_id
  });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for json ingestion \`${element.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_JSON, input }
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const patchJsonIngestion = async (context: AuthContext, user: AuthUser, id: string, patch: object) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_INGESTION_JSON, patch);
  return patched.element;
};

export const ingestionJsonResetState = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  await patchJsonIngestion(context, user, ingestionId, { current_state_hash: '' });
  const ingestionUpdated = await findById(context, user, ingestionId);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `reset state of json ingestion ${ingestionUpdated.name}`,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_JSON, input: ingestionUpdated }
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, ingestionUpdated, user);
};

export const testJsonIngestionMapping = async (context: AuthContext, user: AuthUser, input: IngestionJsonAddInput): Promise<JsonMapperTestResult> => {
  if (input.authentication_value) {
    verifyIngestionAuthenticationContent(input.authentication_type, input.authentication_value);
  }

  // const jsonMapper = await findJsonMapperById(context, user, input.json_mapper_id);
  // const parsedMapper = parseJsonMapper(jsonMapper);
  // const ingestion = {
  //   json_mapper_id: input.json_mapper_id,
  //   uri: input.uri,
  //   authentication_type: input.authentication_type,
  //   authentication_value: input.authentication_value
  // } as BasicStoreEntityIngestionJson;
  // const { jsonLines } = await fetchJsonFromUrl(parsedMapper, ingestion, { limit: 50 });
  // if (parsedMapper.has_header) {
  //   removeHeaderFromFullFile(jsonLines, parsedMapper.skipLineChar);
  // }
  //
  // const bundlerOpts : JsonBundlerTestOpts = {
  //   applicantUser: user,
  //   jsonMapper: parsedMapper
  // };
  // const allObjects = await getJsonTestObjects(context, jsonLines, bundlerOpts);
  const allObjects: any[] = [];
  return {
    objects: JSON.stringify(allObjects, null, 2),
    nbRelationships: allObjects.filter((object: StixObject) => object.type === 'relationship').length,
    nbEntities: allObjects.filter((object: StixObject) => object.type !== 'relationship').length,
  };
};
