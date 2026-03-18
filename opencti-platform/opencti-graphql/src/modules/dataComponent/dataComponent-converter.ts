import { buildStixDomain } from '../../database/stix-2-1-converter';
import { ENTITY_TYPE_DATA_COMPONENT } from '../../schema/stixDomainObject';
import type { Stix2DataComponent, StixDataComponent, StoreEntityDataComponent } from './dataComponent-types';
import { INPUT_DATA_SOURCE } from './dataComponent-types';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { assertType, cleanObject } from '../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';

export const convertDataComponentToStix_2_1 = (instance: StoreEntityDataComponent): StixDataComponent => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    aliases: instance.aliases,
    data_source_ref: instance[INPUT_DATA_SOURCE]?.standard_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'property-extension',
      }),
      [STIX_EXT_MITRE]: {
        extension_type: 'new-sdo',
      },
    },
  };
};

export const convertDataComponentToStix_2_0 = (instance: StoreEntityDataComponent): Stix2DataComponent => {
  assertType(ENTITY_TYPE_DATA_COMPONENT, instance.entity_type);
  const dataComponent = buildStixDomain2(instance);
  const dataSourceStandardId = instance[INPUT_DATA_SOURCE]?.standard_id;
  return {
    ...dataComponent,
    name: instance.name,
    description: instance.description,
    aliases: instance.aliases ?? [],
    x_mitre_data_source_ref: dataSourceStandardId ? `x-mitre-${dataSourceStandardId}` : undefined,
  };
};
