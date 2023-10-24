import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
import type { StixManagerConfiguration, StoreEntityManagerConfiguration } from './managerConfiguration-types';

const convertManagerConfigurationToStix = (instance: StoreEntityManagerConfiguration): StixManagerConfiguration => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    manager_id: instance.manager_id,
    manager_running: instance.manager_running,
    last_run_end_date: instance.last_run_end_date,
    last_run_start_date: instance.last_run_start_date,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertManagerConfigurationToStix;
