import { v4 as uuidv4 } from 'uuid';
import { ENTITY_TYPE_SAVED_FILTER } from './savedFilter-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type InternalObjectModuleDefinition, registerInternalObjectDefinition } from '../../schema/module';
import { authorizedMembers, creators, createdAt } from '../../schema/attribute-definition';

const SAVED_FILTER_DEFINITION: InternalObjectModuleDefinition = {
  type: {
    id: 'saved-filter',
    name: ENTITY_TYPE_SAVED_FILTER,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_SAVED_FILTER]: () => uuidv4(),
    },
  },
  attributes: [
    creators,
    createdAt,
    authorizedMembers,
    {
      name: 'name',
      label: 'Name',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'filters',
      label: 'Filters',
      type: 'string',
      format: 'text',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
    {
      name: 'scope',
      label: 'Scope',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
  ],
  relations: [],
};

registerInternalObjectDefinition(SAVED_FILTER_DEFINITION);
