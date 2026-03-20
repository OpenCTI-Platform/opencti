import { ENTITY_TYPE_DEAD_LETTER_MESSAGE, type StixDeadLetterMessage, type StoreEntityDeadLetterMessage } from './deadLetterMessage-types';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { v4 as uuidv4 } from 'uuid';
import { convertDeadLetterMessageToStix } from './deadLetterMessage-converter';

export const DEAD_LETTER_MESSAGE_DEFINITION: ModuleDefinition<StoreEntityDeadLetterMessage, StixDeadLetterMessage> = {
  type: {
    id: 'dead-letters',
    name: ENTITY_TYPE_DEAD_LETTER_MESSAGE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_DEAD_LETTER_MESSAGE]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'original_connector_id', label: 'OriginalConnectorId', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixDeadLetterMessage) => {
    return stix.original_connector_id ?? '';
  },
  converter_2_1: convertDeadLetterMessageToStix,
};

registerDefinition(DEAD_LETTER_MESSAGE_DEFINITION);
