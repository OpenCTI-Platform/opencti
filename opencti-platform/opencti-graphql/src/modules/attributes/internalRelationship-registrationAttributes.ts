import * as R from 'ramda';
import { type AttributeDefinition, authorizedAuthorities } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { RELATION_ALLOWED_BY, RELATION_IN_PIR, RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ENTITY_TYPE_IDENTITY } from '../../schema/general';

export const pirExplanation: AttributeDefinition = {
  name: 'pir_explanation',
  label: 'PIR Explanations',
  type: 'object',
  format: 'standard',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isFilterable: false,
  mappings: [
    {
      name: 'criterion',
      label: 'PIR explanations criterion',
      type: 'object',
      format: 'flat',
      editDefault: false,
      mandatoryType: 'no',
      multiple: false,
      upsert: true,
      isFilterable: false,
    },
    {
      name: 'dependencies',
      label: 'PIR explanations dependencies',
      type: 'object',
      format: 'standard',
      editDefault: false,
      mandatoryType: 'no',
      multiple: true,
      upsert: true,
      isFilterable: false,
      mappings: [
        {
          name: 'element_id',
          label: 'PIR explanations dependencies element ID',
          type: 'string',
          format: 'id',
          entityTypes: [ABSTRACT_STIX_CORE_RELATIONSHIP],
          editDefault: false,
          mandatoryType: 'no',
          multiple: false,
          upsert: true,
          isFilterable: false,
        },
        {
          name: 'author_id',
          label: 'PIR explanations dependencies author ID',
          type: 'string',
          format: 'id',
          entityTypes: [ENTITY_TYPE_IDENTITY],
          editDefault: false,
          mandatoryType: 'no',
          multiple: false,
          upsert: true,
          isFilterable: false,
        }
      ]
    },
  ]
};

export const internalRelationshipsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [RELATION_PARTICIPATE_TO]: [
    { name: 'start_time', label: 'First observation', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'stop_time', label: 'Last observation', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'confidence', label: 'Confidence', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  [RELATION_ALLOWED_BY]: [
    { name: 'grant', label: 'Grant', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true }
  ],
  [RELATION_IN_PIR]: [
    {
      name: 'pir_score',
      label: 'PIR Score',
      type: 'numeric',
      precision: 'integer',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      isFilterable: true,
    },
    pirExplanation,
    authorizedAuthorities,
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), internalRelationshipsAttributes);
