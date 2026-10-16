import { buildStixObject } from '../../../database/stix-2-1-converter';
import { cleanObject } from '../../../database/stix-converter-utils';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import type { StixHuntRun, StoreEntityHuntRun } from './huntRun-types';

const convertHuntRunToStix = (instance: StoreEntityHuntRun): StixHuntRun => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: `${instance.hunt_run_trigger} run (${instance.hunt_run_status})`,
    hunt_id: instance.hunt_id,
    hunt_run_status: instance.hunt_run_status,
    hunt_run_trigger: instance.hunt_run_trigger,
    verdict: instance.verdict,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertHuntRunToStix;
