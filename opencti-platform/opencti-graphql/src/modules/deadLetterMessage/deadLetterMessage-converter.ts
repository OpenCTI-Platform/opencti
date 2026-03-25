import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { type StixDeadLetterMessage, type StoreEntityDeadLetterMessage } from './deadLetterMessage-types';
import { cleanObject } from '../../database/stix-converter-utils';

export const convertDeadLetterMessageToStix = (instance: StoreEntityDeadLetterMessage): StixDeadLetterMessage => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    original_connector_id: instance.original_connector_id,
    file_id: instance.file_id,
    rejection_info: instance.rejection_info,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};
