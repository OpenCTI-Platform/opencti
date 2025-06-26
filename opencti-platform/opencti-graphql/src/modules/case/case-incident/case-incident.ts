import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT, type StixCaseIncident, type StoreEntityCaseIncident } from './case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case-types';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import { convertCaseIncidentToStix_2_1 } from './case-incident-converter';
import { createdBy, objectAssignee, objectMarking, objectParticipant } from '../../../schema/stixRefRelationship';
import { authorizedMembers, authorizedMembersActivationDate } from '../../../schema/attribute-definition';

const CASE_INCIDENT_DEFINITION: ModuleDefinition<StoreEntityCaseIncident, StixCaseIncident> = {
  type: {
    id: 'case-incident',
    name: ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
    category: ENTITY_TYPE_CONTAINER_CASE,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONTAINER_CASE_INCIDENT]: [{ src: NAME_FIELD }, { src: 'created', dependencies: [NAME_FIELD] }]
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
    { key: 'task', width: 6, label: 'Tasks' },
    { key: 'originOfTheCase', width: 6, label: 'Origin of the case' },
    { key: 'observables', width: 6, label: 'Observables' },
    { key: 'relatedEntities', width: 6, label: 'Related entities' },
    { key: 'externalReferences', width: 6, label: 'External references' },
    { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
    { key: 'notes', width: 12, label: 'Notes about this entity' },
  ],
  attributes: [
    { name: 'created', label: 'Created', type: 'date', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    { name: 'severity', label: 'Severity', type: 'string', format: 'vocabulary', vocabularyCategory: 'case_severity_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'priority', label: 'Priority', type: 'string', format: 'vocabulary', vocabularyCategory: 'case_priority_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'response_types', label: 'Incident response type', type: 'string', format: 'vocabulary', vocabularyCategory: 'incident_response_types_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { ...authorizedMembers, editDefault: true },
    { ...authorizedMembersActivationDate },
  ],
  relations: [],
  relationsRefs: [createdBy, objectMarking, objectAssignee, objectParticipant],
  representative: (stix: StixCaseIncident) => {
    return stix.name;
  },
  converter_2_1: convertCaseIncidentToStix_2_1
};

registerDefinition(CASE_INCIDENT_DEFINITION);
