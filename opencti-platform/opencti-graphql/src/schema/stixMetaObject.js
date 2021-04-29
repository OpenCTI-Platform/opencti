import * as R from 'ramda';
import { ABSTRACT_STIX_META_OBJECT, schemaTypes } from './general';

export const ENTITY_TYPE_MARKING_DEFINITION = 'Marking-Definition';
export const MARKING_DEFINITION_STATEMENT = 'statement';
export const ENTITY_TYPE_LABEL = 'Label';
export const ENTITY_TYPE_EXTERNAL_REFERENCE = 'External-Reference';
export const ENTITY_TYPE_KILL_CHAIN_PHASE = 'Kill-Chain-Phase';

const STIX_META_OBJECT = [
  ENTITY_TYPE_MARKING_DEFINITION,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
];
schemaTypes.register(ABSTRACT_STIX_META_OBJECT, STIX_META_OBJECT);
export const isStixMetaObject = (type) => R.includes(type, STIX_META_OBJECT) || type === ABSTRACT_STIX_META_OBJECT;

export const stixMetaObjectsAttributes = {
  [ENTITY_TYPE_MARKING_DEFINITION]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'x_opencti_stix_ids',
    'spec_version',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
    'created',
    'modified',
    'definition_type',
    'definition',
    'x_opencti_order',
    'x_opencti_color',
  ],
  [ENTITY_TYPE_LABEL]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'x_opencti_stix_ids',
    'spec_version',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
    'created',
    'modified',
    'value',
    'color',
  ],
  [ENTITY_TYPE_EXTERNAL_REFERENCE]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'x_opencti_stix_ids',
    'spec_version',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
    'created',
    'modified',
    'source_name',
    'description',
    'url',
    'hash',
    'external_id',
  ],
  [ENTITY_TYPE_KILL_CHAIN_PHASE]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'x_opencti_stix_ids',
    'spec_version',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
    'created',
    'modified',
    'kill_chain_name',
    'phase_name',
    'x_opencti_order',
  ],
};
R.forEachObjIndexed((value, key) => schemaTypes.registerAttributes(key, value), stixMetaObjectsAttributes);
