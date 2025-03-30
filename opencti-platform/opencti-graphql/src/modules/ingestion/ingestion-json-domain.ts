import * as JSONPath from 'jsonpath-plus';
import type { AuthContext, AuthUser } from '../../types/user';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityIngestionJson, type DataParam, ENTITY_TYPE_INGESTION_JSON } from './ingestion-types';
import { verifyIngestionAuthenticationContent } from './ingestion-common';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';
import { publishUserAction } from '../../listener/UserActionListener';
import { type BasicStoreEntityJsonMapper, ENTITY_TYPE_JSON_MAPPER, type JsonMapperParsed } from '../internal/jsonMapper/jsonMapper-types';
import { type EditInput, IngestionAuthType, type IngestionJsonAddInput, type JsonMapperTestResult } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { StixObject } from '../../types/stix-common';
import { getHttpClient, type GetHttpClient, OpenCTIHeaders } from '../../utils/http-client';
import { isEmptyField, isNotEmptyField, wait } from '../../database/utils';
import { findById as findJsonMapperById } from '../internal/jsonMapper/jsonMapper-domain';
import { SYSTEM_USER } from '../../utils/access';
import jsonMappingExecution from '../../json-mapper';

interface JsonQueryFetchOpts {
  maxResults?: number;
}

const getValueFromPath = (path: string, json: any) => {
  return JSONPath.JSONPath({ path, json, wrap: false, flatten: true });
};
const buildQueryObject = (queryParamsAttributes: Array<DataParam> | undefined, requestData: Record<string, any>, withDefault = true) => {
  const params: Record<string, object> = {};
  if (queryParamsAttributes) {
    for (let attrIndex = 0; attrIndex < queryParamsAttributes.length; attrIndex += 1) {
      const queryParamsAttribute = queryParamsAttributes[attrIndex];
      let attrValue;
      if (queryParamsAttribute.type === 'data') {
        let valueFromPath = getValueFromPath(queryParamsAttribute.from, requestData);
        if (queryParamsAttribute.data_operation === 'count' && valueFromPath) {
          valueFromPath = Array.isArray(valueFromPath) ? valueFromPath.length : 1;
        }
        attrValue = valueFromPath;
      } else {
        attrValue = requestData[queryParamsAttribute.from];
      }
      if (isNotEmptyField(attrValue)) {
        params[queryParamsAttribute.to] = attrValue;
      } else if (isNotEmptyField(queryParamsAttribute.default) && withDefault) {
        params[queryParamsAttribute.to] = queryParamsAttribute.default;
      }
    }
  }
  return params;
};
const buildQueryParams = (queryParamsAttributes: Array<DataParam> | undefined, variables: Record<string, any>) => {
  const params: Record<string, string | number> = {};
  const paramAttributes = (queryParamsAttributes ?? []).filter((query) => query.exposed === 'query_param');
  for (let attrIndex = 0; attrIndex < paramAttributes.length; attrIndex += 1) {
    const queryParamsAttribute = paramAttributes[attrIndex];
    params[queryParamsAttribute.to] = variables[queryParamsAttribute.to];
  }
  return params;
};
const replaceVariables = (body: string, variables: Record<string, object>) => {
  const regex = /\$\w+/g;
  return body.replace(regex, (match) => {
    const variableName = match.substring(1);
    if (Object.prototype.hasOwnProperty.call(variables, variableName)) {
      // If found, return the corresponding value
      // Ensure the returned value is converted to a string if it's not already
      return String(variables[variableName]);
    }
    return match;
  });
};
export const executeJsonQuery = async (context: AuthContext, ingestion: BasicStoreEntityIngestionJson, opts: JsonQueryFetchOpts = {}) => {
  const { maxResults = 0 } = opts;
  let certificates;
  const headers = new OpenCTIHeaders();
  headers.Accept = 'application/json';
  const headerOptions = ingestion.headers ?? [];
  for (let index = 0; index < headerOptions.length; index += 1) {
    const h = headerOptions[index];
    headers[h.name] = h.value;
  }
  if (ingestion.authentication_type === IngestionAuthType.Basic) {
    const auth = Buffer.from(ingestion.authentication_value, 'utf-8').toString('base64');
    headers.Authorization = `Basic ${auth}`;
  }
  if (ingestion.authentication_type === IngestionAuthType.Bearer) {
    headers.Authorization = `Bearer ${ingestion.authentication_value}`;
  }
  if (ingestion.authentication_type === IngestionAuthType.Certificate) {
    certificates = {
      cert: ingestion.authentication_value.split(':')[0],
      key: ingestion.authentication_value.split(':')[1],
      ca: ingestion.authentication_value.split(':')[2]
    };
  }
  const httpClientOptions: GetHttpClient = { headers, rejectUnauthorized: false, responseType: 'json', certificates };
  const httpClient = getHttpClient(httpClientOptions);
  // Execute the http query
  const variables = isEmptyField(ingestion.ingestion_json_state) ? buildQueryObject(ingestion.query_attributes, {}) : ingestion.ingestion_json_state;
  const params = buildQueryParams(ingestion.query_attributes, variables);
  const parsedBody = replaceVariables(ingestion.body, variables);
  logApp.info(`> Main query: ${ingestion.uri}`, parsedBody);
  const { data: requestData, headers: responseHeaders } = await httpClient.call({
    method: ingestion.verb,
    url: ingestion.uri,
    data: parsedBody,
    params
  });
  const jsonMapper = await findJsonMapperById(context, SYSTEM_USER, ingestion.json_mapper_id);
  const jsonMapperParsed: JsonMapperParsed = {
    ...jsonMapper,
    representations: JSON.parse(jsonMapper.representations),
    variables: JSON.parse(jsonMapper.variables)
  };
  const bundle = await jsonMappingExecution({}, requestData, jsonMapperParsed);
  let nextExecutionState = buildQueryObject(ingestion.query_attributes, { ...requestData, ...responseHeaders }, false);
  // region Try to paginate with next page style
  if (ingestion.pagination_with_sub_page && isNotEmptyField(ingestion.pagination_with_sub_page_attribute_path)) {
    let url = getValueFromPath(ingestion.pagination_with_sub_page_attribute_path, requestData);
    while (isNotEmptyField(url) && (maxResults === 0 || (bundle.objects ?? []).length < maxResults)) {
      logApp.info(`> Sub query: ${url}`);
      await wait(100); // Wait 100 ms between 2 calls
      const { data: paginationData } = await httpClient.call({
        method: ingestion.pagination_with_sub_page_query_verb ?? ingestion.verb,
        url,
        data: ingestion.body,
        params
      });
      const paginationVariables = buildQueryObject(ingestion.query_attributes, { ...paginationData, ...responseHeaders }, false);
      nextExecutionState = { ...nextExecutionState, ...paginationVariables };
      const paginationBundle = await jsonMappingExecution({}, paginationData, jsonMapperParsed);
      if (paginationBundle.objects.length > 0) {
        bundle.objects = bundle.objects.concat(paginationBundle.objects);
      }
      url = getValueFromPath(ingestion.pagination_with_sub_page_attribute_path, paginationData);
    }
  }
  // endregion
  // In case of limitation, ensure to not return too many elements
  if (maxResults > 0) {
    bundle.objects = bundle.objects.slice(0, maxResults);
  }
  return { bundle, variables, nextExecutionState };
};

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

export const editIngestionJson = async (context: AuthContext, user: AuthUser, id: string, input: IngestionJsonAddInput) => {
  if (input.authentication_value) {
    verifyIngestionAuthenticationContent(input.authentication_type, input.authentication_value);
  }
  const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_INGESTION_JSON, input);
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

export const testJsonIngestionMapping = async (context: AuthContext, _user: AuthUser, input: IngestionJsonAddInput): Promise<JsonMapperTestResult> => {
  if (input.authentication_value) {
    verifyIngestionAuthenticationContent(input.authentication_type, input.authentication_value);
  }
  const { bundle } = await executeJsonQuery(context, input as BasicStoreEntityIngestionJson, { maxResults: 50 });
  return {
    objects: JSON.stringify(bundle.objects, null, 2),
    nbRelationships: bundle.objects.filter((object: StixObject) => object.type === 'relationship').length,
    nbEntities: bundle.objects.filter((object: StixObject) => object.type !== 'relationship').length,
  };
};
