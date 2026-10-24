import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { createdAt, updatedAt } from '../../schema/attribute-definition';
import { INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG } from '../../config/conf';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';
import {
  ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM,
  IR_ITEM_KINDS,
  IR_ITEM_STATUSES,
  type StixIntelligenceRequirementItem,
  type StoreEntityIntelligenceRequirementItem,
} from './intelligenceRequirementItem-types';

const featureFlag = INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG;

const convertItemToStix = (instance: StoreEntityIntelligenceRequirementItem): StixIntelligenceRequirementItem => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.item_title,
    ir_id: instance.ir_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({ ...stixObject.extensions[STIX_EXT_OCTI], extension_type: 'new-sdo' }),
    },
  };
};

const INTELLIGENCE_REQUIREMENT_ITEM_DEFINITION: ModuleDefinition<StoreEntityIntelligenceRequirementItem, StixIntelligenceRequirementItem> = {
  type: {
    id: 'intelligence-requirement-item',
    name: ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM]: () => uuidv4(),
    },
  },
  attributes: [
    { ...createdAt, featureFlag },
    { ...updatedAt, featureFlag },
    { name: 'ir_id', label: 'Requirement item requirement', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    { name: 'item_kind', label: 'Requirement item kind', type: 'string', format: 'enum', values: IR_ITEM_KINDS, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    { name: 'item_status', label: 'Requirement item status', type: 'string', format: 'enum', values: IR_ITEM_STATUSES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true, featureFlag },
    { name: 'item_title', label: 'Requirement item title', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag },
    { name: 'item_entity_id', label: 'Requirement item entity', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    { name: 'item_entity_type', label: 'Requirement item entity type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    { name: 'item_match_id', label: 'Requirement item match', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag },
    { name: 'item_data', label: 'Requirement item data', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag },
    { name: 'item_result', label: 'Requirement item result', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false, featureFlag },
  ],
  relations: [],
  representative: (stix: StixIntelligenceRequirementItem) => stix.name,
  converter_2_1: convertItemToStix,
};

registerDefinition(INTELLIGENCE_REQUIREMENT_ITEM_DEFINITION);
