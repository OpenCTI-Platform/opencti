import { convertGroupingToStix_2_1 } from './grouping-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { authorizedMembers, authorizedMembersActivationDate } from '../../schema/attribute-definition';
import { RELATION_DERIVED_FROM } from '../../schema/stixCoreRelationship';
import { REL_BUILT_IN } from '../../database/stix';

import { ENTITY_TYPE_CONTAINER_GROUPING, type StixGrouping, type StoreEntityGrouping } from './grouping-types';

const GROUPING_DEFINITION: ModuleDefinition<StoreEntityGrouping, StixGrouping> = {
  type: {
    id: 'groupings',
    name: ENTITY_TYPE_CONTAINER_GROUPING,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONTAINER_GROUPING]: [{ src: NAME_FIELD }, { src: 'context' }, { src: 'created' }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  overviewLayoutCustomization: [
    { key: 'details', width: 6, label: 'Entity details' },
    { key: 'basicInformation', width: 6, label: 'Basic information' },
    { key: 'externalReferences', width: 6, label: 'External references' },
    { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
    { key: 'notes', width: 12, label: 'Notes about this entity' },
  ],
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'content', label: 'Content', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'content_mapping', label: 'Content mapping', format: 'text', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'context', label: 'Context', type: 'string', format: 'vocabulary', vocabularyCategory: 'grouping_context_ov', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { ...authorizedMembers, editDefault: true },
    { ...authorizedMembersActivationDate },
  ],
  relations: [
    {
      name: RELATION_DERIVED_FROM,
      targets: [
        { name: ENTITY_TYPE_CONTAINER_GROUPING, type: REL_BUILT_IN },
      ]
    }
  ],
  representative: (stix: StixGrouping) => {
    return stix.name;
  },
  converter_2_1: convertGroupingToStix_2_1
};

registerDefinition(GROUPING_DEFINITION);
