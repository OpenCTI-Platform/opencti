import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { authorizedMembers, createdAt, creators, lastEventId, updatedAt } from '../../schema/attribute-definition';
import { INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG } from '../../config/conf';
import {
  ENTITY_TYPE_INTELLIGENCE_REQUIREMENT,
  IR_PRIORITIES,
  IR_STATUSES,
  type StixIntelligenceRequirement,
  type StoreEntityIntelligenceRequirement,
} from './intelligenceRequirement-types';
import convertIntelligenceRequirementToStix from './intelligenceRequirement-converter';

const featureFlag = INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG;

const INTELLIGENCE_REQUIREMENT_DEFINITION: ModuleDefinition<StoreEntityIntelligenceRequirement, StixIntelligenceRequirement> = {
  type: {
    id: 'intelligence-requirement',
    name: ENTITY_TYPE_INTELLIGENCE_REQUIREMENT,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT]: () => uuidv4(),
    },
  },
  attributes: [
    { ...lastEventId, featureFlag },
    { ...creators, featureFlag },
    { ...createdAt, featureFlag },
    { ...updatedAt, featureFlag },
    { ...authorizedMembers, featureFlag },
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag },
    { name: 'ir_question', label: 'Requirement question', type: 'string', format: 'text', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag },
    { name: 'ir_priority', label: 'Requirement priority', type: 'string', format: 'enum', values: IR_PRIORITIES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    { name: 'ir_status', label: 'Requirement status', type: 'string', format: 'enum', values: IR_STATUSES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    // The four configuration blocks are stored as serialized JSON (not indexed), parsed by the domain.
    { name: 'ir_kiqs', label: 'Requirement key intelligence questions', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag },
    { name: 'ir_subject_groups', label: 'Requirement subjects', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag },
    { name: 'ir_scope_criteria', label: 'Requirement scope', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag },
    { name: 'ir_relevance_rules', label: 'Requirement relevance', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag },
    { name: 'ir_thresholds', label: 'Requirement score thresholds', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false, featureFlag },
    { name: 'ir_rescan_days', label: 'Requirement rescan in days', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag },
  ],
  relations: [],
  representative: (stix: StixIntelligenceRequirement) => stix.name,
  converter_2_1: convertIntelligenceRequirementToStix,
};

registerDefinition(INTELLIGENCE_REQUIREMENT_DEFINITION);
