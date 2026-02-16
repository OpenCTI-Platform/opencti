import { buildStixObject } from '../../../database/stix-2-1-converter';
import { cleanObject } from '../../../database/stix-converter-utils';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';

const convertWorkflowToStix = (instance: any): any => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertWorkflowToStix;
