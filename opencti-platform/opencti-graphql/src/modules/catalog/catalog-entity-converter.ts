import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import type { StixCatalog, StixCatalogContract, StoreEntityCatalog, StoreEntityCatalogContract } from './catalog-entity-types';

// Catalog and CatalogContract are internal objects. They are never exported as
// real STIX SDOs (registerDefinition does not register a STIX domain converter for
// ABSTRACT_INTERNAL_OBJECT). These converters only produce the minimal internal
// wrapper required by the module framework and the representative resolver.

export const convertCatalogToStix = (instance: StoreEntityCatalog): StixCatalog => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    slug: instance.slug,
    title: instance.title,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export const convertCatalogContractToStix = (instance: StoreEntityCatalogContract): StixCatalogContract => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    slug: instance.slug,
    version: instance.version,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};
