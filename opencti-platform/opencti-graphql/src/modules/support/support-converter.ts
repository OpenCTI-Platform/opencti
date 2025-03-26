import { buildStixObject, cleanObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixSupportPackage, StoreEntitySupportPackage } from './support-types';

const convertSupportPackageToStix = (instance: StoreEntitySupportPackage): StixSupportPackage => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    package_status: instance.package_status,
    package_url: instance.package_url,
    package_upload_dir: instance.package_upload_dir,
    nodes_count: instance.nodes_count,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertSupportPackageToStix;
