import { ENTITY_TYPE_INTERNAL_FILE } from '../../../schema/internalObject';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { type AttributeDefinition, createdAt, creators, entityType, id, internalId, parentTypes, refreshedAt, standardId, updatedAt } from '../../../schema/attribute-definition';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../schema/stixMetaObject';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../../schema/general';
import { UPLOAD_STATUS_VALUES } from './document-domain';

const attributes: Array<AttributeDefinition> = [
  id,
  internalId,
  standardId,
  entityType,
  parentTypes,
  { ...creators, isFilterable: false },
  { ...updatedAt, isFilterable: false },
  { ...refreshedAt, isFilterable: false },
  { ...createdAt, isFilterable: false },
  { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'size', label: 'Size', type: 'numeric', precision: 'long', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'information', label: 'Information', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'lastModified', label: 'Last modification date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'lastModifiedSinceMin', label: 'Last modification since', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'uploadStatus', label: 'Upload status', type: 'string', format: 'enum', values: UPLOAD_STATUS_VALUES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'objectMarking', label: 'Object markings', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_MARKING_DEFINITION], mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
  {
    name: 'metaData',
    label: 'File metadata',
    type: 'object',
    format: 'standard',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: false,
    mappings: [
      { name: 'version', label: 'Version', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'description', label: 'Filename', type: 'string', format: 'text', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'list_filters', label: 'Filters', type: 'string', format: 'text', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'filename', label: 'Filename', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'mimetype', label: 'Mime type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'labels_text', label: 'Workbench labels', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'labels', label: 'Labels', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'encoding', label: 'Encoding', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'creator_id', label: 'Related creator', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
      { name: 'entity_id', label: 'Related entity', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'external_reference_id', label: 'Related external reference', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'messages', label: 'File messages', type: 'object', format: 'flat', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
      { name: 'errors', label: 'File errors', type: 'object', format: 'flat', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
      { name: 'inCarousel', label: 'Include in carousel', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'order', label: 'Carousel order', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'file_markings', label: 'File markings', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_MARKING_DEFINITION], mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
      { name: 'analysis_content_source', label: 'Analysis content source', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'analysis_content_type', label: 'Analysis content type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'analysis_type', label: 'Analysis type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    ]
  },
  // TODO MOVE THAT PART TO A SPECIFIC Place
  // !! Attachment file plugin !!
  // This mapping is only valid for FILES INDEX
  // internalId,
  // name
  { name: 'indexed_at', label: 'Index date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  {
    name: 'attachment',
    label: 'Attachment',
    type: 'object',
    format: 'standard',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: false,
    mappings: [
      { name: 'author', label: 'Author', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'comments', label: 'Comments', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'content', label: 'Content', type: 'string', format: 'text', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'content_length', label: 'Content length', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'content_type', label: 'Content type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'creator_tool', label: 'Creator tool', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'date', label: 'Created date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'format', label: 'Format', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'keywords', label: 'Keywords', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'language', label: 'Language', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'metadata_date', label: 'Metadata date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'modified', label: 'Modified date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'modifier', label: 'Modifier', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'print_date', label: 'Print date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'title', label: 'Title', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    ]
  },
  { name: 'uploaded_at', label: 'Upload date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'file_id', label: 'File identifier', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'entity_id', label: 'Related entity', type: 'string', format: 'id', entityTypes: [ABSTRACT_STIX_CORE_OBJECT], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'removed', label: 'Removed', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
];

schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_INTERNAL_FILE, attributes);
