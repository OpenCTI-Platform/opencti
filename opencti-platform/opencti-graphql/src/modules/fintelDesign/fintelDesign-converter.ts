import type { StixFintelDesign, StoreEntityFintelDesign } from './fintelDesign-types';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';

export const convertFintelDesignToStix = (instance: StoreEntityFintelDesign): StixFintelDesign => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    file_id: instance.file_id,
    gradiantFromColor: instance.gradiantFromColor,
    gradiantToColor: instance.gradiantToColor,
    textColor: instance.textColor,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};
