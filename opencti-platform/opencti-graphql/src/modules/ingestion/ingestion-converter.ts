import { v4 as uuid } from 'uuid';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import type {
  StixIngestionCsv,
  StixIngestionJson,
  StixIngestionRss,
  StixIngestionTaxii,
  StixIngestionTaxiiCollection,
  StoreEntityIngestionCsv,
  StoreEntityIngestionJson,
  StoreEntityIngestionRss,
  StoreEntityIngestionTaxii,
  StoreEntityIngestionTaxiiCollection
} from './ingestion-types';
import { cleanObject } from '../../database/stix-converter-utils';
import type { CsvMapperRepresentationResolved, CsvMapperResolved } from '../internal/csvMapper/csvMapper-types';

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

export const convertIngestionJsonToStix = (instance: StoreEntityIngestionJson): StixIngestionJson => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    uri: instance.uri,
    json_mapper_id: instance.json_mapper_id,
    ingestion_running: instance.ingestion_running,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export const regenerateCsvMapperUUID = (csvMapper: CsvMapperResolved): CsvMapperResolved => {
  const uuidMap: Record<string, string> = {};
  csvMapper.representations.forEach((representation) => {
    const oldId = representation.id;
    uuidMap[oldId] = uuid();
  });
  return {
    ...csvMapper,
    id: uuid(),
    representations: csvMapper.representations.map((representation) => {
      let attributes = {};
      if (representation.attributes) {
        attributes = representation.attributes.map((attribute) => {
          if (attribute?.based_on?.representations) {
            return {
              ...attribute,
              based_on: {
                ...attribute.based_on,
                representations: attribute.based_on.representations.map(
                  (oldId) => uuidMap[oldId] || oldId
                )
              }
            };
          }
          return attribute;
        });
      }

      return {
        ...representation,
        id: uuidMap[representation.id],
        attributes
      } as CsvMapperRepresentationResolved;
    })
  };
};
