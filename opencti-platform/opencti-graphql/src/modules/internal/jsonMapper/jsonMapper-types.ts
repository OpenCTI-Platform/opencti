import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../../types/stix-common';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';

export const ENTITY_TYPE_JSON_MAPPER = 'JsonMapper';

interface AttributeColumnConfiguration {
  separator?: string
  pattern_date?: string
  timezone?: string
}
export interface ComplexPath {
  complex: {
    variables?: { path: string, independent?: boolean, variable: string }[]
    formula: string
  }
  configuration?: AttributeColumnConfiguration
}
export interface AttributePath {
  path: string
  independent?: boolean
  configuration?: AttributeColumnConfiguration
}
interface AttributeBasedOn {
  identifier?: string[]
  representations?: string[]
}
interface AttributeRef {
  multiple: boolean
  id: string
  ids: string[]
}

export interface JsonMapperRepresentationAttribute {
  key: string
  attr_path?: AttributePath | ComplexPath
  based_on?: AttributeBasedOn
  default_values?: string[]
  ref?: AttributeRef
}

interface JsonMapperRepresentationTarget {
  entity_type: string
  path: string
}
export enum JsonMapperRepresentationType {
  Entity = 'entity',
  Relationship = 'relationship',
}
export interface JsonMapperRepresentation {
  id: string
  type: JsonMapperRepresentationType
  target: JsonMapperRepresentationTarget
  identifier?: string[]
  attributes: JsonMapperRepresentationAttribute[]
  from?: string
  to?: string
}

export interface JsonMapperRepresentationAttributeResolved {
  key: string
  json_path?: AttributePath
  based_on?: AttributeBasedOn
  default_values?: { id:string, name:string }[]
  ref?: AttributeRef
}
export interface JsonMapperRepresentationResolved {
  id: string
  type: JsonMapperRepresentationType
  target: JsonMapperRepresentationTarget
  attributes: JsonMapperRepresentationAttributeResolved[]
  from?: string
  to?: string
}

export type JsonMapperParsed = Omit<BasicStoreEntityJsonMapper, 'representations'> & {
  variables: {
    name: string,
    path: ComplexPath
  }[]
  representations: JsonMapperRepresentation[]
  user_chosen_markings?: string[]
};

export type JsonMapperResolved = Omit<BasicStoreEntityJsonMapper, 'representations'> & {
  representations: JsonMapperRepresentationResolved[]
  user_chosen_markings?: string[]
};

export interface BasicStoreEntityJsonMapper extends BasicStoreEntity {
  name: string
  representations: string
}

export interface StoreEntityJsonMapper extends BasicStoreEntityJsonMapper, StoreEntity {}

export interface StixJsonMapper extends StixObject {
  name: string
  representations: string
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
