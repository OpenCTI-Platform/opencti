import type { StoreEntity, BasicStoreEntity } from '../../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../../types/stix-common';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';

export const ENTITY_TYPE_CSV_MAPPER = 'CsvMapper';

interface AttributeColumnConfiguration {
  separator?: string
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

export interface CsvMapperRepresentationAttribute {
  key: string
  column?: AttributeColumn
  based_on?: AttributeBasedOn
  default_values?: string[]
  ref?: AttributeRef
}
export enum Operator {
  Eq = 'eq',
  Neq = 'neq'
}
interface CsvMapperRepresentationTargetColumn {
  column_reference?: string
  operator?: Operator
  value?: string
}
interface CsvMapperRepresentationTarget {
  entity_type: string
  column_based?: CsvMapperRepresentationTargetColumn
}
export enum CsvMapperRepresentationType {
  Entity = 'entity',
  Relationship = 'relationship',
}
export interface CsvMapperRepresentation {
  id: string
  type: CsvMapperRepresentationType
  target: CsvMapperRepresentationTarget
  attributes: CsvMapperRepresentationAttribute[]
  from?: string
  to?: string
}

export interface CsvMapperRepresentationAttributeResolved {
  key: string
  column?: AttributeColumn
  based_on?: AttributeBasedOn
  default_values?: { id:string, name:string }[]
  ref?: AttributeRef
}
export interface CsvMapperRepresentationResolved {
  id: string
  type: CsvMapperRepresentationType
  target: CsvMapperRepresentationTarget
  attributes: CsvMapperRepresentationAttributeResolved[]
  from?: string
  to?: string
}

export type CsvMapperParsed = Omit<BasicStoreEntityCsvMapper, 'representations'> & {
  representations: CsvMapperRepresentation[]
  user_chosen_markings?: string[]
};

export type CsvMapperResolved = Omit<BasicStoreEntityCsvMapper, 'representations'> & {
  representations: CsvMapperRepresentationResolved[]
  user_chosen_markings?: string[]
};

export interface BasicStoreEntityCsvMapper extends BasicStoreEntity {
  name: string
  has_header: boolean
  separator: string
  skipLineChar: string
  representations: string
}

export interface StoreEntityCsvMapper extends BasicStoreEntityCsvMapper, StoreEntity {}

export interface StixCsvMapper extends StixObject {
  name: string
  has_header: boolean
  separator: string
  representations: string
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
