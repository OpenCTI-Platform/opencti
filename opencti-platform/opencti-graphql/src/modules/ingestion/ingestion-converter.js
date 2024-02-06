import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
export const convertIngestionRssToStix = (instance) => {
    const stixObject = buildStixObject(instance);
    return Object.assign(Object.assign({}, stixObject), { name: instance.name, description: instance.description, uri: instance.uri, ingestion_running: instance.ingestion_running, report_types: instance.report_types, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export const convertIngestionTaxiiToStix = (instance) => {
    const stixObject = buildStixObject(instance);
    return Object.assign(Object.assign({}, stixObject), { name: instance.name, description: instance.description, uri: instance.uri, ingestion_running: instance.ingestion_running, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export const convertIngestionCsvToStix = (instance) => {
    const stixObject = buildStixObject(instance);
    return Object.assign(Object.assign({}, stixObject), { name: instance.name, description: instance.description, uri: instance.uri, csv_mapper_id: instance.csv_mapper_id, ingestion_running: instance.ingestion_running, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
