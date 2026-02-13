import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StoreEntity, BasicStoreEntity } from '../../types/store';
import { IngestionAuthType, IngestionCsvMapperType } from '../../generated/graphql';
import type { AuthorizedMember } from '../../utils/access';

// region Rss ingestion
export const ENTITY_TYPE_INGESTION_RSS = 'IngestionRss';

export interface BasicStoreEntityIngestionRss extends BasicStoreEntity {
  name: string;
  description: string;
  scheduling_period: string;
  uri: string;
  user_id: string | undefined;
  created_by_ref: string | undefined;
  report_types: string[];
  object_marking_refs: string[] | undefined;
  current_state_date: Date | undefined;
  ingestion_running: boolean;
  last_execution_date: Date | undefined;
}

export interface StoreEntityIngestionRss extends StoreEntity {
  name: string;
  description: string;
  scheduling_period: string;
  uri: string;
  user_id: string | undefined;
  created_by_ref: string | undefined;
  report_types: string[];
  object_marking_refs: string[] | undefined;
  current_state_date: Date | undefined;
  ingestion_running: boolean;
  last_execution_date: Date | undefined;
}

export interface StixIngestionRss extends StixObject {
  name: string;
  description: string;
  uri: string;
  report_types: string[];
  ingestion_running: boolean;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region Taxii ingestion
export const ENTITY_TYPE_INGESTION_TAXII = 'IngestionTaxii';

export interface BasicStoreEntityIngestionTaxii extends BasicStoreEntity {
  name: string;
  description: string;
  uri: string;
  version: string;
  collection: string;
  confidence_to_score: boolean;
  authentication_type: IngestionAuthType.None | IngestionAuthType.Basic | IngestionAuthType.Bearer | IngestionAuthType.Certificate;
  authentication_value: string;
  user_id: string | undefined;
  added_after_start: Date | undefined;
  current_state_cursor: string | undefined;
  ingestion_running: boolean;
  taxii_more: boolean;
  last_execution_date: Date | undefined;
}

export interface StoreEntityIngestionTaxii extends StoreEntity {
  name: string;
  description: string;
  uri: string;
  version: string;
  collection: string;
  confidence_to_score: boolean;
  authentication_type: IngestionAuthType.None | IngestionAuthType.Basic | IngestionAuthType.Bearer | IngestionAuthType.Certificate;
  authentication_value: string;
  user_id: string | undefined;
  added_after_start: Date | undefined;
  current_state_cursor: string | undefined;
  ingestion_running: boolean;
  taxii_more: boolean;
  last_execution_date: Date | undefined;
}

export interface StixIngestionTaxii extends StixObject {
  name: string;
  description: string;
  uri: string;
  ingestion_running: boolean;
  confidence_to_score: boolean;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region Csv ingestion
export const ENTITY_TYPE_INGESTION_CSV = 'IngestionCsv';

export interface BasicStoreEntityIngestionCsv extends BasicStoreEntity {
  current_state_hash: string;
  name: string;
  description: string;
  scheduling_period: string;
  uri: string;
  csv_mapper_type?: IngestionCsvMapperType.Id | IngestionCsvMapperType.Inline;
  csv_mapper?: string;
  csv_mapper_id?: string;
  authentication_type: IngestionAuthType.None | IngestionAuthType.Basic | IngestionAuthType.Bearer | IngestionAuthType.Certificate;
  authentication_value?: string | null;
  user_id: string | undefined;
  ingestion_running: boolean;
  last_execution_date: Date | undefined;
  markings?: string[];
}

export interface StoreEntityIngestionCsv extends StoreEntity {
  current_state_hash: string;
  name: string;
  description: string;
  uri: string;
  csv_mapper_id: string;
  ingestion_running: boolean;
  last_execution_date: Date | undefined;
  user_id: string | undefined;
}

export interface StixIngestionCsv extends StixObject {
  name: string;
  description: string;
  uri: string;
  csv_mapper_id: string;
  ingestion_running: boolean;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region json ingestion
export const ENTITY_TYPE_INGESTION_JSON = 'IngestionJson';

export interface BasicStoreEntityIngestionJson extends BasicStoreEntity {
  name: string;
  description: string;
  scheduling_period: string;
  uri: string;
  verb: 'get' | 'post';
  body: string;
  json_mapper_id: string;
  confidence_to_score: boolean;
  authentication_type: IngestionAuthType.None | IngestionAuthType.Basic | IngestionAuthType.Bearer | IngestionAuthType.Certificate;
  authentication_value: string | undefined | null;
  user_id: string | undefined;
  ingestion_json_state: Record<string, object>;
  ingestion_running: boolean;
  last_execution_date: Date | undefined;
  headers?: { name: string; value: string }[];
  // pagination
  pagination_with_sub_page: boolean;
  pagination_with_sub_page_attribute_path: string;
  pagination_with_sub_page_query_verb?: 'get' | 'post';
  query_attributes?: Array<DataParam>;
}

export interface StoreEntityIngestionJson extends StoreEntity {
  name: string;
  description: string;
  scheduling_period: string;
  uri: string;
  verb: 'get' | 'post';
  body: string;
  json_mapper_id: string;
  confidence_to_score: boolean;
  authentication_type: IngestionAuthType.None | IngestionAuthType.Basic | IngestionAuthType.Bearer | IngestionAuthType.Certificate;
  authentication_value: string | undefined | null;
  user_id: string | undefined;
  ingestion_json_state: Record<string, object>;
  ingestion_running: boolean;
  last_execution_date: Date | undefined;
  headers?: { name: string; value: string }[];
  // pagination
  pagination_with_sub_page: boolean;
  pagination_with_sub_page_attribute_path: string;
  pagination_with_sub_page_query_verb?: 'get' | 'post';
  query_attributes?: Array<DataParam>;
}

export interface StixIngestionJson extends StixObject {
  name: string;
  description: string;
  uri: string;
  json_mapper_id: string;
  ingestion_running: boolean;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region Taxii ingestion
export const ENTITY_TYPE_INGESTION_TAXII_COLLECTION = 'IngestionTaxiiCollection';

export interface BasicStoreEntityIngestionTaxiiCollection extends BasicStoreEntity {
  name: string;
  description: string;
  user_id: string | undefined;
  confidence_to_score: boolean;
  ingestion_running: boolean;
  restricted_members: Array<AuthorizedMember>;
}

export interface StoreEntityIngestionTaxiiCollection extends StoreEntity {
  name: string;
  description: string;
  user_id: string | undefined;
  confidence_to_score: boolean;
  ingestion_running: boolean;
  restricted_members: Array<AuthorizedMember>;
}

export interface StixIngestionTaxiiCollection extends StixObject {
  name: string;
  description: string;
  ingestion_running: boolean;
  confidence_to_score: boolean;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region Taxii ingestion

export interface DataParam {
  type: 'data' | 'header';
  from: string; // path for data or header name
  to: string; // target variable
  default: string;
  state_operation: 'replace' | 'sum';
  data_operation: 'count' | 'data';
  exposed: 'body' | 'query_param' | 'header';
}
// endregion
