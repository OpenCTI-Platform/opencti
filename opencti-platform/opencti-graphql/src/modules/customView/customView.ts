import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { InternalObjectModuleDefinition } from '../../schema/module';
import { registerInternalObjectDefinition } from '../../schema/module';
import { ENTITY_TYPE_CUSTOM_VIEW } from './customView-types';

export const CUSTOM_VIEW_DEFINITION: InternalObjectModuleDefinition = {
  type: {
    id: 'customView',
    name: ENTITY_TYPE_CUSTOM_VIEW,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CUSTOM_VIEW]: () => uuidv4(),
    },
  },
  attributes: [
    /** Display name to render in UI **/
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    /** Description for admin **/
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    /** Slug used in the URL path **/
    { name: 'slug', label: 'Slug', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    /** Serialized content : layout and widgets **/
    { name: 'manifest', label: 'Manifest', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    /** The entity type for which this custom view applies **/
    { name: 'target_entity_type', label: 'Target entity type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    /** Only enabled custom views are displayed to end users **/
    { name: 'enabled', label: 'Enabled', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    /** One custom view per target_entity_type can be marked as default **/
    { name: 'default', label: 'Default', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [],
};

registerInternalObjectDefinition(CUSTOM_VIEW_DEFINITION);
