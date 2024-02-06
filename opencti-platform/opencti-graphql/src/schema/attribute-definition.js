import { ENTITY_TYPE_USER } from './internalObject';
export const shortMapping = {
    type: 'text',
    fields: {
        keyword: {
            type: 'keyword',
            ignore_above: 512,
            normalizer: 'string_normalizer'
        },
    },
};
export const textMapping = { type: 'text' };
export const dateMapping = { type: 'date' };
export const booleanMapping = { type: 'boolean' };
export const numericMapping = (precision) => ({ type: precision, coerce: false });
// -- GLOBAL --
export const id = {
    name: 'id',
    label: 'Id',
    type: 'string',
    format: 'short',
    mandatoryType: 'no',
    multiple: false,
    editDefault: false,
    upsert: false,
    isFilterable: false,
    ignoreInCreationForm: true,
};
export const internalId = {
    name: 'internal_id',
    label: 'Internal id',
    type: 'string',
    format: 'short',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: false,
};
export const creators = {
    name: 'creator_id',
    label: 'Creators',
    type: 'string',
    format: 'id',
    entityTypes: [ENTITY_TYPE_USER],
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: true,
    isFilterable: true,
};
export const standardId = {
    name: 'standard_id',
    label: 'Id',
    type: 'string',
    format: 'short',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: false,
};
export const iAliasedIds = {
    name: 'i_aliases_ids',
    label: 'Internal aliases',
    type: 'string',
    format: 'short', // Not ID as alias is not really an entity
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: false,
    isFilterable: true,
};
export const files = {
    name: 'x_opencti_files',
    label: 'Files',
    type: 'object',
    format: 'standard',
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: false,
    update: false,
    isFilterable: true,
    mappings: [
        id,
        { name: 'name', label: 'Name', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
        { name: 'description', label: 'Name', type: 'string', format: 'text', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
        { name: 'order', label: 'Order in carousel', type: 'numeric', precision: 'integer', editDefault: false, multiple: false, mandatoryType: 'external', upsert: true, isFilterable: true },
        { name: 'version', label: 'Version', type: 'date', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
        { name: 'mime_type', label: 'Mime type', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
        { name: 'inCarousel', label: 'Include in carousel', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    ]
};
export const authorizedMembers = {
    name: 'authorized_members',
    label: 'Authorized members',
    type: 'object',
    format: 'standard',
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: false,
    isFilterable: false,
    mappings: [
        id,
        { name: 'name', label: 'Name', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
        { name: 'entity_type', label: 'Entity type', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
        { name: 'access_right', label: 'Access right', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
    ]
};
export const authorizedAuthorities = {
    name: 'authorized_authorities',
    label: 'Authorized authorities',
    type: 'string',
    format: 'short', // Not ID as could be anything
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: false,
    isFilterable: false,
};
// -- ENTITY TYPE --
export const parentTypes = {
    name: 'parent_types',
    label: 'Parent types',
    type: 'string',
    format: 'short',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: true,
    upsert: false,
    isFilterable: true,
};
export const baseType = {
    name: 'base_type',
    label: 'Base type',
    type: 'string',
    format: 'short',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
export const entityType = {
    name: 'entity_type',
    label: 'Entity type',
    type: 'string',
    format: 'short',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
export const entityLocationType = {
    name: 'x_opencti_location_type',
    label: 'Location type',
    type: 'string',
    format: 'short',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
export const relationshipType = {
    name: 'relationship_type',
    label: 'Relationship type',
    type: 'string',
    format: 'short',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
export const xOpenctiType = {
    name: 'x_opencti_type',
    label: 'Type',
    type: 'string',
    format: 'short',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
export const errors = {
    name: 'errors',
    label: 'Errors',
    type: 'object',
    format: 'standard',
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: false,
    isFilterable: true,
    mappings: [
        id,
        { name: 'message', label: 'Message', type: 'string', format: 'text', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
        { name: 'error', label: 'Error', type: 'string', format: 'text', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
        { name: 'source', label: 'Source', type: 'string', format: 'text', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
        { name: 'timestamp', label: 'Timestamp', type: 'date', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
    ]
};
// -- STIX DOMAIN OBJECT --
// IDS
export const xOpenctiStixIds = {
    name: 'x_opencti_stix_ids',
    label: 'STIX IDs',
    type: 'string',
    format: 'short', // No ID as self contains internal id of the elements
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: true,
    isFilterable: false,
};
// ALIASES
export const xOpenctiAliases = {
    name: 'x_opencti_aliases',
    label: 'Aliases',
    type: 'string',
    format: 'short',
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: true,
    isFilterable: true,
};
export const aliases = {
    name: 'aliases',
    label: 'Aliases',
    type: 'string',
    format: 'short',
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: true,
    isFilterable: true,
};
// OTHERS
export const created = {
    name: 'created',
    label: 'Created',
    type: 'date',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
export const modified = {
    name: 'modified',
    label: 'Modified',
    type: 'date',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
export const createdAt = {
    name: 'created_at',
    label: 'Created at',
    type: 'date',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
export const updatedAt = {
    name: 'updated_at',
    label: 'Updated at',
    type: 'date',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
export const revoked = {
    name: 'revoked',
    label: 'Revoked',
    type: 'boolean',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: true,
    isFilterable: true,
};
export const confidence = {
    name: 'confidence',
    label: 'Confidence',
    type: 'numeric',
    precision: 'integer',
    mandatoryType: 'no',
    editDefault: true,
    multiple: false,
    scalable: true,
    upsert: true,
    isFilterable: true,
};
export const xOpenctiReliability = {
    name: 'x_opencti_reliability',
    label: 'Reliability',
    type: 'string',
    format: 'short',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
export const lang = {
    name: 'lang',
    label: 'Lang',
    type: 'string',
    format: 'short',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
export const identityClass = {
    name: 'identity_class',
    label: 'Identity class',
    type: 'string',
    format: 'short',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
};
