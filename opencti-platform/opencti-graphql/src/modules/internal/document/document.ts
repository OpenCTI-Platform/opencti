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
    format: 'standard',
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
      { name: 'messages', label: 'File messages', type: 'object', format: 'flat', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      { name: 'errors', label: 'File errors', type: 'object', format: 'flat', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      { name: 'inCarousel', label: 'Include in carousel', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'order', label: 'Carousel order', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    ]
  },
  // TODO MOVE THAT PART TO A SPECIFIC Place
  // !! Attachment file plugin !!
  // This mapping is only valid for FILES INDEX
  // internalId,
  // name
  { name: 'indexed_at', label: 'Index date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  {
    name: 'attachment',
    label: 'Attachment',
    type: 'object',
    format: 'standard',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
    mappings: [
      { name: 'author', label: 'Author', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'comments', label: 'Comments', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'content', label: 'Content', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'content_length', label: 'Content length', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'content_type', label: 'Content type', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'creator_tool', label: 'Creator tool', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'date', label: 'Created date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'description', label: 'Description', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'format', label: 'Format', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'keywords', label: 'Keywords', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'language', label: 'Language', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'metadata_date', label: 'Metadata date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'modified', label: 'Modified date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'modifier', label: 'Modifier', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'print_date', label: 'Print date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'title', label: 'Title', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    ]
  },
  { name: 'uploaded_at', label: 'Upload date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'file_id', label: 'File identifier', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'entity_id', label: 'Related entity', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
];

schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_INTERNAL_FILE, attributes);
