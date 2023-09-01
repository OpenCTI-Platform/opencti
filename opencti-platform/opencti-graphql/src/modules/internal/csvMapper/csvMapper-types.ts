import type { StoreEntity, BasicStoreEntity } from '../../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../../types/stix-common';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';

export const ENTITY_TYPE_CSV_MAPPER = 'CsvMapper';

interface AttributeColumnConfiguration {
  seperator?: string
  pattern_date?: string
  timezone?: string
}
export interface AttributeColumn {
  column_name: string
  configuration?: AttributeColumnConfiguration
}
interface AttributeBasedOn {
  representations?: string[]
}
interface AttributeRef {
  multiple: boolean
  id: string
  ids: string[]
}

interface CsvMapperRepresentationAttribute {
  key: string
  column?: AttributeColumn
  based_on?: AttributeBasedOn
  ref?: AttributeRef
}
export enum Operator {
  eq,
  neq,
}
interface CsvMapperRepresentationTargetColumn {
  column_reference: string
  operator: Operator
  value: string
}
interface CsvMapperRepresentationTarget {
  entity_type: string
  column_based?: CsvMapperRepresentationTargetColumn
}
export enum CsvMapperRepresentationType {
  entity = 'entity',
  relationship = 'relationship',
}
export interface CsvMapperRepresentation {
  id: string
  type: CsvMapperRepresentationType
  target: CsvMapperRepresentationTarget
  attributes: CsvMapperRepresentationAttribute[]
  from?: string
  to?: string
}
export interface BasicStoreEntityCsvMapper extends BasicStoreEntity {
  name: string
  has_header: boolean
  separator: string
  representations: CsvMapperRepresentation[]
}

export interface StoreEntityCsvMapper extends BasicStoreEntityCsvMapper, StoreEntity {}

export interface StixCsvMapper extends StixObject {
  name: string
  has_header: boolean
  separator: string
  representations: CsvMapperRepresentation[]
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
