import { v4 as uuidv4 } from 'uuid';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { StixForm, StoreEntityForm } from './form-types';
import { ENTITY_TYPE_FORM } from './form-types';
import { convertFormToStix } from './form-converter';

export const FORM_DEFINITION: ModuleDefinition<StoreEntityForm, StixForm> = {
  type: {
    id: 'forms',
    name: ENTITY_TYPE_FORM,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_FORM]: () => uuidv4(),
    },
  },
  attributes: [
    {
      name: 'name',
      label: 'Name',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: true,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'main_entity_type',
      label: 'Main entity type',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: true,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'description',
      label: 'Description',
      type: 'string',
      format: 'text',
      mandatoryType: 'customizable',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'form_schema',
      label: 'Form Schema',
      type: 'string',
      format: 'json',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
      schemaDef: {
        type: 'object',
        properties: {
          version: { type: 'string' },
          mainEntityType: { type: 'string' },
          fields: { type: 'array' },
        },
        required: ['version', 'mainEntityType', 'fields'],
      }
    },
    {
      name: 'active',
      label: 'Active',
      type: 'boolean',
      mandatoryType: 'customizable',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
  ],
  relations: [],
  relationsRefs: [],
  representative: (stix: StixForm) => {
    return stix.name;
  },
  converter_2_1: convertFormToStix,
};

registerDefinition(FORM_DEFINITION);
