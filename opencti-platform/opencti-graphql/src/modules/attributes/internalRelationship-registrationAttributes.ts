import * as R from 'ramda';
import { type AttributeDefinition, authorizedAuthorities } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { RELATION_ALLOWED_BY, RELATION_IN_PIR, RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';

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
    {
      name: 'pir_explanations',
      label: 'PIR Explanations',
      type: 'object',
      format: 'flat',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: true,
      isFilterable: true,
    },
    authorizedAuthorities,
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), internalRelationshipsAttributes);
