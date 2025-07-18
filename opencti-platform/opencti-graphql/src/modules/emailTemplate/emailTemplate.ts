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
import { ENTITY_TYPE_EMAIL_TEMPLATE, type StixEmailTemplate, type StoreEntityEmailTemplate } from './emailTemplate-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import convertEmailTemplateToStix from './emailTemplate-converter';

const EMAIL_TEMPLATE_DEFINITION: ModuleDefinition<StoreEntityEmailTemplate, StixEmailTemplate> = {
  type: {
    id: 'emailTemplate',
    name: ENTITY_TYPE_EMAIL_TEMPLATE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_EMAIL_TEMPLATE]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    { name: 'email_object', label: 'Email Object', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'sender_email', label: 'Sender email', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'template_body', label: 'Template body', type: 'string', format: 'text', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixEmailTemplate) => {
    return stix.name;
  },
  converter_2_1: convertEmailTemplateToStix
};

registerDefinition(EMAIL_TEMPLATE_DEFINITION);
