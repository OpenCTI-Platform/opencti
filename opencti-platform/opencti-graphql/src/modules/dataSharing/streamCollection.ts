import { v4 as uuidv4 } from 'uuid';
import convertStreamCollectionToStix from './streamCollection-converter';
import { ENTITY_TYPE_STREAM_COLLECTION, type StoreEntityStreamCollection, type StixStreamCollection } from './streamCollection-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { authorizedMembers } from '../../schema/attribute-definition';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';

const STREAM_COLLECTION_DEFINITION: ModuleDefinition<StoreEntityStreamCollection, StixStreamCollection> = {
  type: {
    id: 'stream-collection',
    name: ENTITY_TYPE_STREAM_COLLECTION,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_STREAM_COLLECTION]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'filters', label: 'Filters', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'stream_public', label: 'Public stream', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'stream_public_user_id', label: 'Public stream user id', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    { name: 'stream_live', label: 'Is live', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    authorizedMembers,
  ],
  relations: [],
  representative: (instance: StixStreamCollection) => {
    return instance.name;
  },
  converter_2_1: convertStreamCollectionToStix,
};

registerDefinition(STREAM_COLLECTION_DEFINITION);
