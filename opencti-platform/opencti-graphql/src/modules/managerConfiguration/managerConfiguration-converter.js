import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
const convertManagerConfigurationToStix = (instance) => {
    const stixObject = buildStixObject(instance);
    return Object.assign(Object.assign({}, stixObject), { manager_id: instance.manager_id, manager_running: instance.manager_running, manager_setting: instance.manager_setting, last_run_end_date: instance.last_run_end_date, last_run_start_date: instance.last_run_start_date, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertManagerConfigurationToStix;
