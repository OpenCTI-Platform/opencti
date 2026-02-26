import type { Mutable } from '../types/type-utils';

// List of fields extracted by the attachment ingest processor.
// The full list is available in the Elasticsearch docs:
// (https://www.elastic.co/guide/en/elasticsearch/reference/8.19/attachment.html#attachment-fields).
export const ATTACHMENT_PROCESSOR_EXTRACTED_PROPS_ELASTICSEARCH = [
  'content',
  'title',
  'author',
  'keywords',
  'date',
  'content_type',
  'content_length',
  'language',
  'modified',
  'format',
  // identifier,     NOT EXTRACTED
  // contributor,    NOT EXTRACTED
  // coverage,       NOT EXTRACTED
  'modifier',
  'creator_tool',
  // publisher,      NOT EXTRACTED
  // relation,       NOT EXTRACTED
  // rights,         NOT EXTRACTED
  // source,         NOT EXTRACTED
  // type,           NOT EXTRACTED
  'description',
  'print_date',
  'metadata_date',
  // latitude,       NOT EXTRACTED
  // longitude,      NOT EXTRACTED
  // altitude,       NOT EXTRACTED
  // rating,         NOT EXTRACTED
  'comments',
] as const;

// List of fields extracted by the attachment ingest processor, for OpenSearch.
// The full list is available in the OS docs:
// (https://docs.opensearch.org/latest/install-and-configure/additional-plugins/ingest-attachment-plugin/#extracted-information),
// and code shows the check rejects unknown fields with an exception:
// https://github.com/opensearch-project/OpenSearch/blob/315481148edaa43410e2e9f1801ec903fd62ec20/plugins/ingest-attachment/src/main/java/org/opensearch/ingest/attachment/AttachmentProcessor.java#L277
export const ATTACHMENT_PROCESSOR_EXTRACTED_PROPS_OPENSEARCH = [
  'content',
  'title',
  'author',
  'keywords',
  'date',
  'content_type',
  'content_length',
  'language',
] as const;

// Union type of all properties extracted by the ES or OS attachment processor
export type AttachmentProcessorExtractedProp = Mutable<typeof ATTACHMENT_PROCESSOR_EXTRACTED_PROPS_ELASTICSEARCH>[number]
  | Mutable<typeof ATTACHMENT_PROCESSOR_EXTRACTED_PROPS_OPENSEARCH>[number];
