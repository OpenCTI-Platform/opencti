import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { createdAt, updatedAt } from '../../schema/attribute-definition';
import { INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG } from '../../config/conf';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';
import {
  ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH,
  IR_MATCH_STATUSES,
  type StixIntelligenceRequirementMatch,
  type StoreEntityIntelligenceRequirementMatch,
} from './intelligenceRequirementMatch-types';

const featureFlag = INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG;

const convertMatchToStix = (instance: StoreEntityIntelligenceRequirementMatch): StixIntelligenceRequirementMatch => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.match_entity_id,
    ir_id: instance.ir_id,
    match_entity_id: instance.match_entity_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({ ...stixObject.extensions[STIX_EXT_OCTI], extension_type: 'new-sdo' }),
    },
  };
};

const INTELLIGENCE_REQUIREMENT_MATCH_DEFINITION: ModuleDefinition<StoreEntityIntelligenceRequirementMatch, StixIntelligenceRequirementMatch> = {
  type: {
    id: 'intelligence-requirement-match',
    name: ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    // One match per (requirement, entity)
    definition: {
      [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH]: [{ src: 'ir_id' }, { src: 'match_entity_id' }],
    },
    resolvers: {},
  },
  attributes: [
    { ...createdAt, featureFlag },
    { ...updatedAt, featureFlag },
    { name: 'ir_id', label: 'Requirement match requirement', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    { name: 'match_entity_id', label: 'Requirement match entity', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    { name: 'match_entity_name', label: 'Requirement match entity name', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    { name: 'match_entity_type', label: 'Requirement match entity type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    { name: 'match_status', label: 'Requirement match status', type: 'string', format: 'enum', values: IR_MATCH_STATUSES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true, featureFlag },
    { name: 'match_criteria_ids', label: 'Requirement match criteria', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true, featureFlag },
    { name: 'match_explanations', label: 'Requirement match explanations', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false, featureFlag },
    { name: 'match_score', label: 'Requirement match score', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true, featureFlag },
    { name: 'match_score_breakdown', label: 'Requirement match score breakdown', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false, featureFlag },
    { name: 'match_excluded', label: 'Requirement match excluded', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true, featureFlag },
    { name: 'match_history', label: 'Requirement match history', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false, featureFlag },
    { name: 'match_last_fact_at', label: 'Requirement match last fact', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true, featureFlag },
  ],
  relations: [],
  representative: (stix: StixIntelligenceRequirementMatch) => stix.match_entity_id,
  converter_2_1: convertMatchToStix,
};

registerDefinition(INTELLIGENCE_REQUIREMENT_MATCH_DEFINITION);
