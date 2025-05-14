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

import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_INGESTION_JSON, type StixIngestionJson, type StoreEntityIngestionJson } from './ingestion-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { convertIngestionJsonToStix } from './ingestion-converter';
import { ENTITY_TYPE_JSON_MAPPER } from '../internal/jsonMapper/jsonMapper-types';

const INGESTION_JSON_DEFINITION: ModuleDefinition<StoreEntityIngestionJson, StixIngestionJson> = {
  type: {
    id: 'ingestion-json',
    name: ENTITY_TYPE_INGESTION_JSON,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INGESTION_JSON]: () => uuidv4(),
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'scheduling_period', label: 'Scheduling period', type: 'string', format: 'text', mandatoryType: 'no', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'uri', label: 'Uri', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'body', label: 'body', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'verb', label: 'verb', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'pagination_with_sub_page', label: 'Sub pagination activation', type: 'boolean', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'pagination_with_sub_page_attribute_path', label: 'Sub pagination uri path', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'pagination_with_sub_page_query_verb', label: 'Sub pagination verb', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'headers', label: 'Headers', type: 'object', format: 'flat', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'query_attributes', label: 'Query attributes', type: 'object', format: 'flat', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'user_id', label: 'User_id', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'json_mapper_id', label: 'Json_mapper_id', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_JSON_MAPPER], mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'ingestion_running', label: 'Ingestion_running', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'ingestion_json_state', label: 'Ingestion state', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'markings', label: 'Markings', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: true, upsert: true, isFilterable: false },
    { name: 'authentication_type', label: 'Authentication type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_execution_date', label: 'Last execution date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'authentication_value', label: 'Authentication value', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixIngestionJson) => {
    return stix.name;
  },
  converter_2_1: convertIngestionJsonToStix
};

registerDefinition(INGESTION_JSON_DEFINITION);
