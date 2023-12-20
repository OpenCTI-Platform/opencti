import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT, type StixCaseIncident, type StoreEntityCaseIncident } from './case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case-types';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import convertCaseIncidentToStix from './case-incident-converter';
import { createdBy, objectAssignee, objectMarking, objectParticipant } from '../../../schema/stixRefRelationship';
import { created } from '../../../schema/attribute-definition';

const CASE_INCIDENT_DEFINITION: ModuleDefinition<StoreEntityCaseIncident, StixCaseIncident> = {
  type: {
    id: 'case-incident',
    name: ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
    category: ENTITY_TYPE_CONTAINER_CASE,
    aliased: false
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
    { ...created, mandatoryType: 'external', editDefault: true, upsert: true },
    { name: 'severity', label: 'Severity', type: 'string', format: 'vocabulary', vocabularyCategory: 'case_severity_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'priority', label: 'Priority', type: 'string', format: 'vocabulary', vocabularyCategory: 'case_priority_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'response_types', label: 'Incident response type', type: 'string', format: 'vocabulary', vocabularyCategory: 'incident_response_types_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [createdBy, objectMarking, objectAssignee, objectParticipant],
  representative: (stix: StixCaseIncident) => {
    return stix.name;
  },
  converter: convertCaseIncidentToStix
};

registerDefinition(CASE_INCIDENT_DEFINITION);
