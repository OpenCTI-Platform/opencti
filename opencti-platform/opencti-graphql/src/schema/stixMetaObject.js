import * as R from 'ramda';
import { ABSTRACT_STIX_META_OBJECT } from './general';

export const ENTITY_TYPE_MARKING_DEFINITION = 'Marking-Definition';
export const ENTITY_TYPE_LABEL = 'Label';
export const ENTITY_TYPE_EXTERNAL_REFERENCE = 'External-Reference';
export const ENTITY_TYPE_KILL_CHAIN_PHASE = 'Kill-Chain-Phase';

const STIX_META_OBJECT = [
  ENTITY_TYPE_MARKING_DEFINITION,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
];
export const isStixMetaObject = (type) => R.includes(type, STIX_META_OBJECT) || type === ABSTRACT_STIX_META_OBJECT;
