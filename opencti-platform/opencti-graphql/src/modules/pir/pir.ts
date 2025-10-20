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
import { ENTITY_TYPE_PIR, PIR_TYPES, type StixPir, type StoreEntityPir } from './pir-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import convertEntityPirToStix from './pir-converter';
import { authorizedMembers, draftChange, lastEventId } from '../../schema/attribute-definition';

const ENTITY_PIR_DEFINITION: ModuleDefinition<StoreEntityPir, StixPir> = {
  type: {
    id: 'pir',
    name: ENTITY_TYPE_PIR,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_PIR]: () => uuidv4()
    },
  },
  attributes: [
    lastEventId,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'pir_type', label: 'PIR Type', type: 'string', format: 'enum', values: PIR_TYPES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'pir_rescan_days', label: 'PIR Rescan in days', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'pir_criteria', label: 'PIR Criteria', type: 'object', format: 'flat', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'pir_filters', label: 'PIR Filters', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    authorizedMembers,
    { ...draftChange, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixPir) => stix.name,
  converter_2_1: convertEntityPirToStix
};

registerDefinition(ENTITY_PIR_DEFINITION);
