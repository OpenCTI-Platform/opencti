import { buildRefRelationKey, ID_INFERRED, ID_INTERNAL } from './general';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { schemaRelationsRefDefinition } from './schema-relationsRef';
import { bodyMultipart, externalReferences, isStixRefRelationship, killChainPhases, objectLabel } from './stixRefRelationship';
export const isSingleRelationsRef = (entityType, databaseName) => isStixRefRelationship(databaseName)
    && !schemaRelationsRefDefinition.isMultipleDatabaseName(entityType, databaseName);
// eslint-disable-next-line
export const instanceMetaRefsExtractor = (relationshipType, isInferred, data) => {
    var _a;
    const refField = isStixRefRelationship(relationshipType) && isInferred ? ID_INFERRED : ID_INTERNAL;
    const field = buildRefRelationKey(relationshipType, refField);
    const anyData = data; // TODO JRI Find a way to not use any
    return (_a = anyData[field]) !== null && _a !== void 0 ? _a : [];
};
const RELATIONS_STIX_ATTRIBUTES = ['source_ref', 'target_ref', 'sighting_of_ref', 'where_sighted_refs'];
const RELATIONS_EMBEDDED_STIX_ATTRIBUTES = [
    externalReferences.stixName, killChainPhases.stixName, objectLabel.stixName, bodyMultipart.stixName
];
// eslint-disable-next-line
export const stixRefsExtractor = (data) => {
    var _a, _b;
    if (!((_b = (_a = data.extensions) === null || _a === void 0 ? void 0 : _a[STIX_EXT_OCTI]) === null || _b === void 0 ? void 0 : _b.type)) {
        return [];
    }
    const stixNames = schemaRelationsRefDefinition.getStixNames(data.extensions[STIX_EXT_OCTI].type)
        .filter((key) => !RELATIONS_EMBEDDED_STIX_ATTRIBUTES.includes(key))
        .concat(RELATIONS_STIX_ATTRIBUTES);
    return stixNames.map((key) => {
        if (key === 'granted_refs' && data.extensions[STIX_EXT_OCTI][key]) {
            return data.extensions[STIX_EXT_OCTI][key];
        }
        return data[key] || [];
    }).flat();
};
