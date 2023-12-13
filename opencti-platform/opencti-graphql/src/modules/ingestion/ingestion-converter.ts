import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
import type { StixIngestionCsv, StixIngestionRss, StixIngestionTaxii, StoreEntityIngestionCsv, StoreEntityIngestionRss } from './ingestion-types';

export const convertIngestionRssToStix = (instance: StoreEntityIngestionRss): StixIngestionRss => {
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

export const convertIngestionTaxiiToStix = (instance: StoreEntityIngestionRss): StixIngestionTaxii => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    uri: instance.uri,
    ingestion_running: instance.ingestion_running,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export const convertIngestionCsvToStix = (instance: StoreEntityIngestionCsv): StixIngestionCsv => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    uri: instance.uri,
    mapper: instance.mapper,
    ingestion_running: instance.ingestion_running,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};
