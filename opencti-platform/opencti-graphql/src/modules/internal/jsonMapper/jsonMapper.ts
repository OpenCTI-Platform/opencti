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
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import type { StixJsonMapper, StoreEntityJsonMapper } from './jsonMapper-types';
import { ENTITY_TYPE_JSON_MAPPER } from './jsonMapper-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { normalizeName } from '../../../schema/identifier';
import convertJsonMapperToStix from './jsonMapper-converter';

const CSV_MAPPER_DEFINITION: ModuleDefinition<StoreEntityJsonMapper, StixJsonMapper> = {
  type: {
    id: 'jsonmapper',
    name: ENTITY_TYPE_JSON_MAPPER,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_JSON_MAPPER]: () => uuidv4()
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'variables', label: 'Variables', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'representations', label: 'Representations', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (instance: StixJsonMapper) => {
    return instance.name;
  },
  converter_2_1: convertJsonMapperToStix
};

registerDefinition(CSV_MAPPER_DEFINITION);
