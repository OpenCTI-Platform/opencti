import { ENTITY_TYPE_INTERNAL_FILE } from '../../../schema/internalObject';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { type AttributeDefinition, entityType, id, internalId, standardId } from '../../../schema/attribute-definition';

const attributes: Array<AttributeDefinition> = [
  id,
  internalId,
  standardId,
  entityType,
  { name: 'name', label: 'Name', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'size', label: 'Size', type: 'numeric', precision: 'long', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'information', label: 'Information', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'lastModified', label: 'Last modification date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'lastModifiedSinceMin', label: 'Last modification since', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'uploadStatus', label: 'Upload status', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  {
    name: 'metaData',
    label: 'File metadata',
    type: 'object',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
    mappings: [
      { name: 'version', label: 'Version', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'filename', label: 'Filename', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'mimetype', label: 'Mime type', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'encoding', label: 'Encoding', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'creator_id', label: 'Related creator', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'entity_id', label: 'Related entity', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'messages', label: 'File messages', type: 'object_flat', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      { name: 'errors', label: 'File errors', type: 'object_flat', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    ]
  },
];

schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_INTERNAL_FILE, attributes);
