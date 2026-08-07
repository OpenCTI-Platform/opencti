import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import type {
  StixCatalogContract,
  StixCatalogLogo,
  StixCatalogManifest,
  StoreEntityCatalogContract,
  StoreEntityCatalogLogo,
  StoreEntityCatalogManifest,
} from './catalog-entity-types';

// CatalogContract is an internal object. It is never exported as a real STIX SDO.
// This converter produces the minimal internal wrapper required by the module framework.

export const convertCatalogContractToStix = (instance: StoreEntityCatalogContract): StixCatalogContract => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    slug: instance.slug,
    version: instance.version,
    title: instance.title,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export const convertCatalogLogoToStix = (instance: StoreEntityCatalogLogo): StixCatalogLogo => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    hash: instance.hash,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export const convertCatalogManifestToStix = (instance: StoreEntityCatalogManifest): StixCatalogManifest => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    source_uri: instance.source_uri,
    catalog_id: instance.catalog_id,
    revision: instance.revision,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};
