import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import type { StixDataSanity, StoreEntityDataSanity } from './dataSanity-types';
import { cleanObject } from '../../database/stix-converter-utils';

const convertDataSanityToStix = (instance: StoreEntityDataSanity): StixDataSanity => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    operation_name: instance.operation_name,
    last_run_date: instance.last_run_date,
    last_execution_time: instance.last_execution_time,
    last_failure_message: instance.last_failure_message,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertDataSanityToStix;
