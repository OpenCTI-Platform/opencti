import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { authorizedMembers, createdAt, creators, lastEventId, updatedAt } from '../../schema/attribute-definition';
import {
  ENTITY_TYPE_INTELLIGENCE_REQUIREMENT,
  IR_PRIORITIES,
  IR_STATUSES,
  IR_BRIEF_FREQUENCIES,
  type StixIntelligenceRequirement,
  type StoreEntityIntelligenceRequirement,
} from './intelligenceRequirement-types';
import convertIntelligenceRequirementToStix from './intelligenceRequirement-converter';

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
    { ...lastEventId },
    { ...creators },
    { ...createdAt },
    { ...updatedAt },
    { ...authorizedMembers },
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'ir_question', label: 'Requirement question', type: 'string', format: 'text', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'ir_priority', label: 'Requirement priority', type: 'string', format: 'enum', values: IR_PRIORITIES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'ir_status', label: 'Requirement status', type: 'string', format: 'enum', values: IR_STATUSES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    // The four configuration blocks are stored as serialized JSON (not indexed), parsed by the domain.
    { name: 'ir_kiqs', label: 'Requirement key intelligence questions', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'ir_subject_groups', label: 'Requirement subjects', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'ir_scope_criteria', label: 'Requirement scope', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'ir_relevance_rules', label: 'Requirement relevance', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'ir_thresholds', label: 'Requirement score thresholds', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'ir_rescan_days', label: 'Requirement rescan in days', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'ir_brief_frequency', label: 'Requirement brief frequency', type: 'string', format: 'enum', values: IR_BRIEF_FREQUENCIES, mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'ir_processing', label: 'Requirement processing', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'ir_pir_id', label: 'Requirement driven PIR', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'ir_last_brief_at', label: 'Requirement last brief date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixIntelligenceRequirement) => stix.name,
  converter_2_1: convertIntelligenceRequirementToStix,
};

registerDefinition(INTELLIGENCE_REQUIREMENT_DEFINITION);
