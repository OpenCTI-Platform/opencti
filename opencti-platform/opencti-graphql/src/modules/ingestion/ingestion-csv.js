import { v4 as uuidv4 } from 'uuid';
import { registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_INGESTION_CSV } from './ingestion-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { normalizeName } from '../../schema/identifier';
import { convertIngestionCsvToStix } from './ingestion-converter';
const INGESTION_CSV_DEFINITION = {
    type: {
        id: 'ingestion-csv',
        name: ENTITY_TYPE_INGESTION_CSV,
        category: ABSTRACT_INTERNAL_OBJECT,
        aliased: false
    },
    identifier: {
        definition: {
            [ENTITY_TYPE_INGESTION_CSV]: () => uuidv4(),
        },
        resolvers: {
            name(data) {
                return normalizeName(data);
            },
        },
    },
    attributes: [
        { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'description', label: 'Description', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'uri', label: 'Uri', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'user_id', label: 'User_id', type: 'string', format: 'id', entityTypes: ['user'], mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
        { name: 'csv_mapper_id', label: 'Csv_mapper_id', type: 'string', format: 'id', entityTypes: ['csvMapper'], mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'ingestion_running', label: 'Ingestion_running', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'added_after_start', label: 'Added_after_start', type: 'date', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'current_state_hash', label: 'Current_state_hash', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    ],
    relations: [],
    representative: (stix) => {
        return stix.name;
    },
    converter: convertIngestionCsvToStix
};
registerDefinition(INGESTION_CSV_DEFINITION);
