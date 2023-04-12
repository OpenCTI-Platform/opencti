import * as R from 'ramda';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION
} from '../../schema/stixMetaObject';

const stixMetaObjectsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [ENTITY_TYPE_MARKING_DEFINITION]: [
    { name: 'definition_type', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'definition', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'x_opencti_order', type: 'numeric', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'x_opencti_color', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_LABEL]: [
    { name: 'value', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'color', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  [ENTITY_TYPE_EXTERNAL_REFERENCE]: [
    { name: 'source_name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'url', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'hash', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'external_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_KILL_CHAIN_PHASE]: [
    { name: 'kill_chain_name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'phase_name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'x_opencti_order', type: 'numeric', mandatoryType: 'external', multiple: false, upsert: true },
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), stixMetaObjectsAttributes);
