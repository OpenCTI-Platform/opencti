import { ENTITY_TYPE_CONTAINER_CASE } from '../case-types';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import { createdBy, objectAssignee, objectMarking, objectParticipant } from '../../../schema/stixRefRelationship';
import type { StixCaseRfi, StoreEntityCaseRfi } from './case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from './case-rfi-types';
import convertCaseRfiToStix from './case-rfi-converter';

const CASE_RFI_DEFINITION: ModuleDefinition<StoreEntityCaseRfi, StixCaseRfi> = {
  type: {
    id: 'case-rfi',
    name: ENTITY_TYPE_CONTAINER_CASE_RFI,
    category: ENTITY_TYPE_CONTAINER_CASE,
    aliased: false
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
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'created', label: 'Created', type: 'date', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    { name: 'information_types', label: 'Information types', type: 'string', format: 'vocabulary', vocabularyCategory: 'request_for_information_types_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'severity', label: 'Severity', type: 'string', format: 'vocabulary', vocabularyCategory: 'case_severity_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'priority', label: 'Priority', type: 'string', format: 'vocabulary', vocabularyCategory: 'case_priority_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [createdBy, objectMarking, objectAssignee, objectParticipant],
  representative: (stix: StixCaseRfi) => {
    return stix.name;
  },
  converter: convertCaseRfiToStix
};

registerDefinition(CASE_RFI_DEFINITION);
