import { v4 as uuidv4 } from 'uuid';
import convertFeedToStix from './feed-converter';
import { ENTITY_TYPE_FEED, type StoreEntityFeed, type StixFeed } from './feed-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { authorizedMembers } from '../../schema/attribute-definition';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';

const FEED_DEFINITION: ModuleDefinition<StoreEntityFeed, StixFeed> = {
  type: {
    id: 'feed',
    name: ENTITY_TYPE_FEED,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_FEED]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'filters', label: 'Filters', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'separator', label: 'Separator', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'rolling_time', label: 'Rolling time', type: 'numeric', precision: 'long', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'include_header', label: 'Include header', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'feed_public', label: 'Public feed', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'feed_public_user_id', label: 'Public feed user id', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    { name: 'feed_types', label: 'Feed types', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: true, upsert: false, isFilterable: true },
    { name: 'feed_date_attribute', label: 'Selected attribute date', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    {
      name: 'feed_attributes',
      label: 'Feed attributes',
      type: 'object',
      format: 'standard',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: true,
      mappings: [
        { name: 'attribute', label: 'Attribute', type: 'string', format: 'short', editDefault: false, mandatoryType: 'internal', multiple: false, upsert: true, isFilterable: true },
        { name: 'multi_match_strategy', label: 'Multi-match strategy', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
        { name: 'multi_match_separator', label: 'Multi-match separator', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
        {
          name: 'mappings',
          label: 'Mappings',
          type: 'object',
          format: 'standard',
          editDefault: false,
          mandatoryType: 'internal',
          multiple: true,
          upsert: true,
          isFilterable: false,
          mappings: [
            { name: 'type', label: 'Type', type: 'string', format: 'short', editDefault: false, mandatoryType: 'internal', multiple: false, upsert: true, isFilterable: false },
            { name: 'attribute', label: 'Attribute', type: 'string', format: 'short', editDefault: false, mandatoryType: 'internal', multiple: false, upsert: true, isFilterable: false },
            { name: 'relationship_type', label: 'Relationship type', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
            { name: 'target_entity_type', label: 'Target entity type', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
          ],
        },
      ],
    },
    authorizedMembers,
  ],
  relations: [],
  representative: (instance: StixFeed) => {
    return instance.name;
  },
  converter_2_1: convertFeedToStix,
};

registerDefinition(FEED_DEFINITION);
