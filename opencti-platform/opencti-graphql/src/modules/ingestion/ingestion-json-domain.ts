/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import * as JSONPath from 'jsonpath-plus';
import type { AuthContext, AuthUser } from '../../types/user';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityIngestionJson, type DataParam, ENTITY_TYPE_INGESTION_JSON, type StoreEntityIngestionJson } from './ingestion-types';
import { addAuthenticationCredentials, removeAuthenticationCredentials, verifyIngestionAuthenticationContent } from './ingestion-common';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { connectorIdFromIngestId, registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';
import { publishUserAction } from '../../listener/UserActionListener';
import { type BasicStoreEntityJsonMapper, ENTITY_TYPE_JSON_MAPPER, type JsonMapperParsed } from '../internal/jsonMapper/jsonMapper-types';
import { type EditInput, IngestionAuthType, type IngestionJsonAddInput, type JsonMapperTestResult } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { getHttpClient, type GetHttpClient, OpenCTIHeaders } from '../../utils/http-client';
import { isEmptyField, isNotEmptyField, wait } from '../../database/utils';
import { findById as findJsonMapperById } from '../internal/jsonMapper/jsonMapper-domain';
import { SYSTEM_USER } from '../../utils/access';
import jsonMappingExecution from '../../parser/json-mapper';
import type { StixObject } from '../../types/stix-2-1-common';
import { getEntitiesMapFromCache } from '../../database/cache';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_USER } from '../../schema/internalObject';

interface JsonQueryFetchOpts {
  maxResults?: number;
}

const getValueFromPath = (path: string, json: any) => {
  return JSONPath.JSONPath({ path, json, wrap: false, flatten: true });
};
const buildQueryObject = (queryParamsAttributes: Array<DataParam> | undefined, requestData: Record<string, any>, withDefault = true) => {
  const params: Record<string, object | string> = {};
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

const replaceVariables = (body: string, variables: Record<string, object | string>) => {
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

const filterVariablesForAttributes = (attributes: Array<DataParam>, variables: Record<string, object | string>, exposed: 'body' | 'query_param' | 'header') => {
  const params: Record<string, object | string> = {};
  const paramAttributes = attributes.filter((query) => query.exposed === exposed);
  for (let attrIndex = 0; attrIndex < paramAttributes.length; attrIndex += 1) {
    const queryParamsAttribute = paramAttributes[attrIndex];
    params[queryParamsAttribute.to] = variables[queryParamsAttribute.to];
  }
  return params;
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
  // Prepare headers
  const variables = isEmptyField(ingestion.ingestion_json_state) ? buildQueryObject(ingestion.query_attributes, {}) : ingestion.ingestion_json_state;
  const headerVariables = filterVariablesForAttributes(ingestion.query_attributes ?? [], variables, 'header');
  Object.entries(headerVariables).forEach(([k, v]) => {
    headers[k] = String(v);
  });
  if (ingestion.authentication_type === IngestionAuthType.Basic) {
    const auth = Buffer.from(IngestionAuthType.Basic, 'utf-8').toString('base64');
    headers.Authorization = `Basic ${auth}`;
  }
  if (ingestion.authentication_type === IngestionAuthType.Bearer) {
    headers.Authorization = `Bearer ${IngestionAuthType.Bearer}`;
  }
  if (ingestion.authentication_type === IngestionAuthType.Certificate) {
    certificates = {
      cert: IngestionAuthType.Certificate.split(':')[0],
      key: IngestionAuthType.Certificate.split(':')[1],
      ca: IngestionAuthType.Certificate.split(':')[2],
    };
  }
  const httpClientOptions: GetHttpClient = { headers, rejectUnauthorized: false, responseType: 'json', certificates };
  const httpClient = getHttpClient(httpClientOptions);
  // Prepare query params
  const queryVariables = filterVariablesForAttributes(ingestion.query_attributes ?? [], variables, 'query_param');
  const parsedUri = replaceVariables(ingestion.uri, queryVariables);
  // Prepare body
  const bodyVariables = filterVariablesForAttributes(ingestion.query_attributes ?? [], variables, 'body');
  const parsedBody = replaceVariables(ingestion.body, bodyVariables);
  // Execute the http query
  logApp.info(`> Main query: ${parsedUri}`, { body: parsedBody });
  const { data: requestData, headers: responseHeaders } = await httpClient.call({
    method: ingestion.verb,
    url: parsedUri,
    data: parsedBody,
  });
  const jsonMapper = await findJsonMapperById(context, SYSTEM_USER, ingestion.json_mapper_id);
  const jsonMapperParsed: JsonMapperParsed = {
    ...jsonMapper,
    representations: JSON.parse(jsonMapper.representations),
    variables: jsonMapper.variables ? JSON.parse(jsonMapper.variables) : [],
  };
  const platformUsers = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const ingestionUser = ingestion.user_id ? platformUsers.get(ingestion.user_id) : null;
  const bundle = await jsonMappingExecution(context, ingestionUser || SYSTEM_USER, requestData, jsonMapperParsed);
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
      });
      const paginationVariables = buildQueryObject(ingestion.query_attributes, { ...paginationData, ...responseHeaders }, false);
      nextExecutionState = { ...nextExecutionState, ...paginationVariables };
      const paginationBundle = await jsonMappingExecution(context, ingestionUser || SYSTEM_USER, paginationData, jsonMapperParsed);
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

export const findById = async (context: AuthContext, user: AuthUser, ingestionId: string, removeCredentials = false) => {
  const jsonIngestion = await storeLoadById<BasicStoreEntityIngestionJson>(context, user, ingestionId, ENTITY_TYPE_INGESTION_JSON);

  if (removeCredentials) {
    jsonIngestion.authentication_value = removeAuthenticationCredentials(jsonIngestion.authentication_type, jsonIngestion.authentication_value) || '';
  }
  return jsonIngestion;
};

export const findJsonIngestionPaginated = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return pageEntitiesConnection<BasicStoreEntityIngestionJson>(context, user, [ENTITY_TYPE_INGESTION_JSON], opts);
};

export const findAllJsonIngestion = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return fullEntitiesList<BasicStoreEntityIngestionJson>(context, user, [ENTITY_TYPE_INGESTION_JSON], opts);
};

export const findJsonMapperForIngestionById = (context: AuthContext, user: AuthUser, jsonMapperId: string) => {
  return storeLoadById<BasicStoreEntityJsonMapper>(context, user, jsonMapperId, ENTITY_TYPE_JSON_MAPPER);
};

export const deleteIngestionJson = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  const deleted = await deleteElementById<StoreEntityIngestionJson>(context, user, ingestionId, ENTITY_TYPE_INGESTION_JSON);
  await unregisterConnectorForIngestion(context, deleted.id);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes json ingestion \`${deleted.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_JSON, input: deleted },
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
      connector_user_id: input.user_id,
    });
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates json ingestion \`${input.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION_JSON, input },
    });
  }
  return element;
};

export const editIngestionJson = async (context: AuthContext, user: AuthUser, id: string, input: IngestionJsonAddInput) => {
  let authenticationValue = input.authentication_value;
  if (authenticationValue && input.authentication_type) {
    const { authentication_value } = await findById(context, user, id);
    verifyIngestionAuthenticationContent(input.authentication_type, authenticationValue);
    authenticationValue = addAuthenticationCredentials(
      authentication_value,
      authenticationValue,
      input.authentication_type,
    );
  }

  const { element } = await patchAttribute<StoreEntityIngestionJson>(context, user, id, ENTITY_TYPE_INGESTION_JSON, {
    ...input,
    authentication_value: authenticationValue,
  });
  return {
    ...element,
    authentication_value: removeAuthenticationCredentials(input.authentication_type as IngestionAuthType, authenticationValue),
  };
};

export const ingestionJsonEditField = async (context: AuthContext, user: AuthUser, ingestionId: string, input: EditInput[]) => {
  const patchInput = [...input];

  if (input.some((editInput) => editInput.key === 'authentication_value')) {
    const { authentication_value, authentication_type } = await findById(context, user, ingestionId);
    const authenticationValueField = input.find((editInput) => editInput.key === 'authentication_value');
    if (authenticationValueField?.value[0]) {
      verifyIngestionAuthenticationContent(authentication_type, authenticationValueField?.value[0]);
    }
    const updatedAuthenticationValue = addAuthenticationCredentials(
      authentication_value,
      authenticationValueField?.value[0],
      authentication_type,
    );

    const updatedInput = patchInput.map((editInput) => {
      if (editInput.key === 'authentication_value') {
        return {
          ...editInput,
          value: [updatedAuthenticationValue],
        };
      }
      return editInput;
    });

    patchInput.splice(0, patchInput.length, ...updatedInput);
  }

  // Reset `authentication_value` on `authentication_type` change
  if (input.some((editInput) => editInput.key === 'authentication_type')) {
    const resetAuthenticationValue: EditInput = {
      key: 'authentication_value',
      value: [''],
    };
    patchInput.push(resetAuthenticationValue);
  }

  const { element } = await updateAttribute<StoreEntityIngestionJson>(context, user, ingestionId, ENTITY_TYPE_INGESTION_JSON, patchInput);
  await registerConnectorForIngestion(context, {
    id: element.id,
    type: 'JSON',
    name: element.name,
    is_running: element.ingestion_running ?? false,
    connector_user_id: element.user_id,
  });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for json ingestion \`${element.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_JSON, input },
  });

  const notif = await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
  return {
    ...notif,
    authentication_value: removeAuthenticationCredentials(notif.authentication_type, notif.authentication_value),
  };
};

export const patchJsonIngestion = async (context: AuthContext, user: AuthUser, id: string, patch: object) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_INGESTION_JSON, patch);
  return patched.element;
};

export const ingestionJsonResetState = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  await patchJsonIngestion(context, user, ingestionId, { ingestion_json_state: null });
  const ingestion = await findById(context, user, ingestionId);
  const connectorId = connectorIdFromIngestId(ingestion.id);
  await patchAttribute(context, SYSTEM_USER, connectorId, ENTITY_TYPE_CONNECTOR, { connector_state: null });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `reset state of json ingestion ${ingestion.name}`,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_JSON, input: ingestion },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, ingestion, user);
};

export const testJsonIngestionMapping = async (context: AuthContext, _user: AuthUser, input: IngestionJsonAddInput): Promise<JsonMapperTestResult> => {
  if (input.authentication_value) {
    verifyIngestionAuthenticationContent(input.authentication_type, input.authentication_value);
  }
  const { bundle, nextExecutionState } = await executeJsonQuery(context, input as BasicStoreEntityIngestionJson, { maxResults: 50 });
  return {
    objects: JSON.stringify(bundle.objects, null, 2),
    nbRelationships: bundle.objects.filter((object: StixObject) => object.type === 'relationship').length,
    nbEntities: bundle.objects.filter((object: StixObject) => object.type !== 'relationship').length,
    state: JSON.stringify(nextExecutionState),
  };
};
