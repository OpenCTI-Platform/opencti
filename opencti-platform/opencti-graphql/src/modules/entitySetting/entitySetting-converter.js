import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
const convertEntitySettingToStix = (instance) => {
    const stixObject = buildStixObject(instance);
    return Object.assign(Object.assign({}, stixObject), { target_type: instance.target_type, platform_entity_files_ref: instance.platform_entity_files_ref, platform_hidden_type: instance.platform_hidden_type, enforce_reference: instance.enforce_reference, attributes_configuration: instance.attributes_configuration, available_settings: instance.availableSettings, workflow_configuration: instance.workflow_configuration, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertEntitySettingToStix;
