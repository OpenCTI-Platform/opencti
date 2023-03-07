import { ABSTRACT_STIX_META_OBJECT } from './general';
import { schemaTypesDefinition } from './schema-types';

export const ENTITY_TYPE_LABEL = 'Label';
export const ENTITY_TYPE_EXTERNAL_REFERENCE = 'External-Reference';
export const ENTITY_TYPE_KILL_CHAIN_PHASE = 'Kill-Chain-Phase';
export const ENTITY_TYPE_MARKING_DEFINITION = 'Marking-Definition';

export const STIX_EMBEDDED_OBJECT = [ENTITY_TYPE_LABEL, ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE];
const STIX_META_OBJECT = [...STIX_EMBEDDED_OBJECT, ENTITY_TYPE_MARKING_DEFINITION];
schemaTypesDefinition.register(ABSTRACT_STIX_META_OBJECT, [...STIX_META_OBJECT, ABSTRACT_STIX_META_OBJECT]);

export const isStixMetaObject = (type: string) => schemaTypesDefinition.isTypeIncludedIn(type, ABSTRACT_STIX_META_OBJECT)
|| type === ABSTRACT_STIX_META_OBJECT;
