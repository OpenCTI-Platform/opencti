import caseRfiTypeDefs from './case-rfi.graphql';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case-types';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import { createdBy, objectAssignee, objectMarking, objectParticipant } from '../../../schema/stixRefRelationship';
import type { StixCaseRfi, StoreEntityCaseRfi } from './case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from './case-rfi-types';
import convertCaseRfiToStix from './case-rfi-converter';
import caseRfiResolvers from './case-rfi-resolvers';

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
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'created', type: 'date', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'information_types', type: 'string', mandatoryType: 'customizable', multiple: true, upsert: true, label: 'information_types' },
    { name: 'severity', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'priority', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
  ],
  relations: [],
  relationsRefs: [createdBy, objectMarking, objectAssignee, objectParticipant],
  representative: (stix: StixCaseRfi) => {
    return stix.name;
  },
  converter: convertCaseRfiToStix
};

registerDefinition(CASE_RFI_DEFINITION);
