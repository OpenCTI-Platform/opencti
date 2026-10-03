import { buildStixObject } from '../../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { cleanObject } from '../../../database/stix-converter-utils';
import type { StixDefenseLogsourceMapping, StoreEntityDefenseLogsourceMapping } from './defenseLogsourceMapping-types';

const convertDefenseLogsourceMappingToStix = (instance: StoreEntityDefenseLogsourceMapping): StixDefenseLogsourceMapping => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    logsource_category: instance.logsource_category,
    logsource_product: instance.logsource_product,
    logsource_service: instance.logsource_service,
    data_components: instance.data_components,
    active: instance.active,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertDefenseLogsourceMappingToStix;
