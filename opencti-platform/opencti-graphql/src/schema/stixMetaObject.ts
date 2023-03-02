import * as R from 'ramda';
import { ABSTRACT_STIX_META_OBJECT } from './general';
import {
  AttributeDefinition,
  created,
  createdAt,
  entityType,
  internalId, modified,
  specVersion,
  standardId,
  updatedAt,
  xOpenctiStixIds
} from './attribute-definition';
import { schemaAttributesDefinition } from './schema-attributes';

export const ENTITY_TYPE_LABEL = 'Label';
export const ENTITY_TYPE_EXTERNAL_REFERENCE = 'External-Reference';
export const ENTITY_TYPE_KILL_CHAIN_PHASE = 'Kill-Chain-Phase';
export const ENTITY_TYPE_MARKING_DEFINITION = 'Marking-Definition';

export const STIX_EMBEDDED_OBJECT = [ENTITY_TYPE_LABEL, ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE];
const STIX_META_OBJECT = [...STIX_EMBEDDED_OBJECT, ENTITY_TYPE_MARKING_DEFINITION];
schemaAttributesDefinition.register(ABSTRACT_STIX_META_OBJECT, [...STIX_META_OBJECT, ABSTRACT_STIX_META_OBJECT]);

export const isStixMetaObject = (type: string) => schemaAttributesDefinition.get(ABSTRACT_STIX_META_OBJECT).includes(type)
|| type === ABSTRACT_STIX_META_OBJECT;

const stixMetaObjectsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [ENTITY_TYPE_MARKING_DEFINITION]: [
    internalId,
    standardId,
    entityType,
    xOpenctiStixIds,
    specVersion,
    createdAt,
    updatedAt,
    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    created,
    modified,
    { name: 'definition_type', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'definition', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'x_opencti_order', type: 'numeric', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'x_opencti_color', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_LABEL]: [
    internalId,
    standardId,
    entityType,
    xOpenctiStixIds,
    specVersion,
    createdAt,
    updatedAt,
    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    created,
    modified,
    { name: 'value', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'color', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  [ENTITY_TYPE_EXTERNAL_REFERENCE]: [
    internalId,
    standardId,
    entityType,
    xOpenctiStixIds,
    specVersion,
    createdAt,
    updatedAt,
    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    created,
    modified,
    { name: 'source_name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'url', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'hash', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'external_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_KILL_CHAIN_PHASE]: [
    internalId,
    standardId,
    entityType,
    xOpenctiStixIds,
    specVersion,
    createdAt,
    updatedAt,
    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    created,
    modified,
    { name: 'kill_chain_name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'phase_name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'x_opencti_order', type: 'numeric', mandatoryType: 'external', multiple: false, upsert: true },
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), stixMetaObjectsAttributes);
