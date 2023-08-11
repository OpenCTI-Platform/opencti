import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
import type { StixIngestion, StoreEntityIngestion } from './ingestion-types';

export const convertIngestionToStix = (instance: StoreEntityIngestion): StixIngestion => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    uri: instance.uri,
    ingestion_running: instance.ingestion_running,
    report_types: instance.report_types,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};
