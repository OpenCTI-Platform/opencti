import caseRfiTypeDefs from './case-rfi.graphql';
import { ENTITY_TYPE_CONTAINER_CASE_RFI, StixCaseRfi, StoreEntityCaseRfi } from './case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case-types';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import caseRfiResolvers from './case-rfi-resolvers';
import convertCaseRfiToStix from './case-rfi-converter';
import { createdBy, objectAssignee, objectMarking } from '../../../schema/stixRefRelationship';

const CASE_RFI_DEFINITION: ModuleDefinition<StoreEntityCaseRfi, StixCaseRfi> = {
  type: {
    id: 'case-rfi',
    name: ENTITY_TYPE_CONTAINER_CASE_RFI,
    category: ENTITY_TYPE_CONTAINER_CASE,
    aliased: false
  },
  graphql: {
    schema: caseRfiTypeDefs,
    resolver: caseRfiResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONTAINER_CASE_RFI]: [{ src: NAME_FIELD }, { src: 'created' }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'created', type: 'date', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'severity', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'priority', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'response_types', type: 'string', mandatoryType: 'customizable', multiple: true, upsert: true, label: 'Rfi type' },
  ],
  relations: [],
  relationsRefs: [createdBy, objectMarking, objectAssignee],
  representative: (stix: StixCaseRfi) => {
    return stix.name;
  },
  converter: convertCaseRfiToStix
};

registerDefinition(CASE_RFI_DEFINITION);
