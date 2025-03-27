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
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_DISSEMINATION_LIST, type StixDisseminationList, type StoreEntityDisseminationList } from './disseminationList-types';
import convertDisseminationListToStix from './disseminationList-converter';

const DISSEMINATION_LIST_DEFINITION: ModuleDefinition<StoreEntityDisseminationList, StixDisseminationList> = {
  type: {
    id: 'disseminationList',
    name: ENTITY_TYPE_DISSEMINATION_LIST,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_DISSEMINATION_LIST]: () => uuidv4()
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'emails', label: 'Emails', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixDisseminationList) => {
    return stix.name;
  },
  converter_2_1: convertDisseminationListToStix
};

registerDefinition(DISSEMINATION_LIST_DEFINITION);
