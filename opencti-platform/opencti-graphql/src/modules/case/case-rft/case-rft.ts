import caseRftTypeDefs from './case-rft.graphql';
import { ENTITY_TYPE_CONTAINER_CASE_RFT, StixCaseRft, StoreEntityCaseRft } from './case-rft-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case-types';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import caseRftResolvers from './case-rft-resolvers';
import convertCaseRftToStix from './case-rft-converter';
import { createdBy, objectAssignee, objectMarking } from '../../../schema/stixRefRelationship';

const CASE_RFT_DEFINITION: ModuleDefinition<StoreEntityCaseRft, StixCaseRft> = {
  type: {
    id: 'case-rft',
    name: ENTITY_TYPE_CONTAINER_CASE_RFT,
    category: ENTITY_TYPE_CONTAINER_CASE,
    aliased: false
  },
  graphql: {
    schema: caseRftTypeDefs,
    resolver: caseRftResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONTAINER_CASE_RFT]: [{ src: NAME_FIELD }, { src: 'created' }]
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
    { name: 'response_types', type: 'string', mandatoryType: 'customizable', multiple: true, upsert: true, label: 'Rft type' },
  ],
  relations: [],
  relationsRefs: [createdBy, objectMarking, objectAssignee],
  representative: (stix: StixCaseRft) => {
    return stix.name;
  },
  converter: convertCaseRftToStix
};

registerDefinition(CASE_RFT_DEFINITION);
