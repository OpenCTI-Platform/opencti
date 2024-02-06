import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
export const ENTITY_TYPE_CSV_MAPPER = 'CsvMapper';
export var Operator;
(function (Operator) {
    Operator[Operator["eq"] = 0] = "eq";
    Operator[Operator["neq"] = 1] = "neq";
})(Operator || (Operator = {}));
export var CsvMapperRepresentationType;
(function (CsvMapperRepresentationType) {
    CsvMapperRepresentationType["entity"] = "entity";
    CsvMapperRepresentationType["relationship"] = "relationship";
})(CsvMapperRepresentationType || (CsvMapperRepresentationType = {}));
