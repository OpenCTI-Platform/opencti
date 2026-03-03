import { v4 as uuidv4 } from 'uuid';
import { normalizeName } from '../../schema/identifier';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { authorizedMembers } from '../../schema/attribute-definition';
import convertCustomViewToStix from './customView-converter';
import { ENTITY_TYPE_CUSTOM_VIEW, type StixCustomView, type StoreEntityCustomView } from './customView-types';
import { isFeatureEnabled } from '../../config/conf';

export const CUSTOM_VIEW_DEFINITION: ModuleDefinition<StoreEntityCustomView, StixCustomView> = {
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
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'manifest', label: 'Manifest', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    authorizedMembers,
  ],
  relations: [],
  relationsRefs: [],
  representative: (stix: StixCustomView) => {
    return stix.name;
  },
  converter_2_1: convertCustomViewToStix,
};

const isCustomViewEnabled = isFeatureEnabled('CUSTOM_VIEW');

if (isCustomViewEnabled) {
  registerDefinition(CUSTOM_VIEW_DEFINITION);
}
