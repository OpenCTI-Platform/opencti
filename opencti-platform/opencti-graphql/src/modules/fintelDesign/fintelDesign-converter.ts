import type { StixFintelDesign, StoreEntityFintelDesign } from './fintelDesign-types';
import { buildStixObject, cleanObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const convertFintelDesignToStix = (instance: StoreEntityFintelDesign): StixFintelDesign => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    url: instance.url,
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
