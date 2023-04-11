import caseIncidentTypeDefs from './case-incident.graphql';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT, StixCaseIncident, StoreEntityCaseIncident } from './case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case-types';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import caseIncidentResolvers from './case-incident-resolvers';
import convertCaseIncidentToStix from './case-incident-converter';
import { createdBy, objectAssignee, objectMarking } from '../../../schema/stixMetaRelationship';

const CASE_INCIDENT_DEFINITION: ModuleDefinition<StoreEntityCaseIncident, StixCaseIncident> = {
  type: {
    id: 'case-incident',
    name: ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
    category: ENTITY_TYPE_CONTAINER_CASE,
    aliased: false
  },
  graphql: {
    schema: caseIncidentTypeDefs,
    resolver: caseIncidentResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONTAINER_CASE_INCIDENT]: [{ src: NAME_FIELD }, { src: 'created' }]
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
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'severity', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'priority', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'response_types', type: 'string', mandatoryType: 'customizable', multiple: true, upsert: true },
    { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  relations: [],
  relationsRefs: [createdBy, objectMarking, objectAssignee],
  representative: (stix: StixCaseIncident) => {
    return stix.name;
  },
  converter: convertCaseIncidentToStix
};

registerDefinition(CASE_INCIDENT_DEFINITION);
