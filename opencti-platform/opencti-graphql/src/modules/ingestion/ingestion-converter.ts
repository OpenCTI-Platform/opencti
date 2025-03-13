import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-2-1-converter';
import type {
  StixIngestionCsv,
  StixIngestionRss,
  StixIngestionTaxii,
  StixIngestionTaxiiCollection,
  StoreEntityIngestionCsv,
  StoreEntityIngestionRss,
  StoreEntityIngestionTaxii,
  StoreEntityIngestionTaxiiCollection
} from './ingestion-types';

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

export const convertIngestionTaxiiToStix = (instance: StoreEntityIngestionTaxii): StixIngestionTaxii => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    uri: instance.uri,
    ingestion_running: instance.ingestion_running,
    confidence_to_score: instance.confidence_to_score,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export const convertIngestionTaxiiCollectionToStix = (instance: StoreEntityIngestionTaxiiCollection): StixIngestionTaxiiCollection => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    ingestion_running: instance.ingestion_running,
    confidence_to_score: instance.confidence_to_score,
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
    csv_mapper_id: instance.csv_mapper_id,
    ingestion_running: instance.ingestion_running,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};
