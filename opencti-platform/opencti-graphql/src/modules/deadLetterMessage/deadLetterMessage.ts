import { ENTITY_TYPE_DEAD_LETTER_MESSAGE, type StixDeadLetterMessage, type StoreEntityDeadLetterMessage } from './deadLetterMessage-types';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { v4 as uuidv4 } from 'uuid';
import { convertDeadLetterMessageToStix } from './deadLetterMessage-converter';

export const DEAD_LETTER_MESSAGE_DEFINITION: ModuleDefinition<StoreEntityDeadLetterMessage, StixDeadLetterMessage> = {
  type: {
    id: 'dead-letter-message',
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
    { name: 'original_connector_id', label: 'OriginalConnectorId', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    {
      name: 'rejection_info',
      label: 'Rejection info',
      type: 'object',
      format: 'standard',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
      mappings: [
        { name: 'reject_reason', label: 'Rejection reason', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'last_error_msg', label: 'Last error message', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      ],
    },
    { name: 'file_id', label: 'File Id', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixDeadLetterMessage) => {
    return stix.original_connector_id ?? '';
  },
  converter_2_1: convertDeadLetterMessageToStix,
};

registerDefinition(DEAD_LETTER_MESSAGE_DEFINITION);
