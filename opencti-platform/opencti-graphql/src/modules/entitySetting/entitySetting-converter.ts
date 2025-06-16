import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixEntitySetting, StoreEntityEntitySetting } from './entitySetting-types';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';

const convertEntitySettingToStix = (instance: StoreEntityEntitySetting): StixEntitySetting => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    target_type: instance.target_type,
    platform_entity_files_ref: instance.platform_entity_files_ref,
    platform_hidden_type: instance.platform_hidden_type,
    enforce_reference: instance.enforce_reference,
    attributes_configuration: instance.attributes_configuration,
    available_settings: instance.availableSettings,
    workflow_configuration: instance.workflow_configuration,
    request_access_workflow: instance.request_access_workflow,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertEntitySettingToStix;
