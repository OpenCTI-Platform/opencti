import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixEntitySetting, StoreEntityEntitySetting } from './entitySetting-types';
import { buildStixObject, cleanObject } from '../../database/stix-converter';

const convertEntitySettingToStix = (instance: StoreEntityEntitySetting): StixEntitySetting => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    target_type: instance.target_type,
    platform_entity_files_ref: instance.platform_entity_files_ref,
    platform_hidden_type: instance.platform_hidden_type,
    enforce_reference: instance.enforce_reference,
    attributes_configuration: instance.attributes_configuration,
    confidence_scale: instance.confidence_scale,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertEntitySettingToStix;
