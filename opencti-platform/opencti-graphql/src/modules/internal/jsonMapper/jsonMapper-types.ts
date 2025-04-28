/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import type { AttributeRef } from '../../../generated/graphql';

export const ENTITY_TYPE_JSON_MAPPER = 'JsonMapper';

interface AttributeColumnConfiguration {
  separator?: string
  pattern_date?: string
  timezone?: string
}
export interface ComplexAttributePath {
  formula: string
  variables?: { path: string, independent?: boolean, variable: string }[]
  configuration?: AttributeColumnConfiguration
}
export interface SimpleAttributePath {
  path: string
  independent?: boolean
  configuration?: AttributeColumnConfiguration
}
interface AttributeBasedOn {
  identifier?: string
  representations?: string[]
}

export interface JsonMapperRepresentationAttribute {
  key: string
  mode: 'simple' | 'complex' | 'base'
  default_values?: string[]
}

export interface JsonMapperRepresentationAttributeResolved {
  key: string
  mode: 'simple' | 'complex' | 'base'
  default_values?: { id:string, name:string }[]
  ref?: AttributeRef
}

export interface SimpleRepresentationAttribute extends JsonMapperRepresentationAttribute {
  mode: 'simple'
  attr_path?: SimpleAttributePath
}

export interface ComplexRepresentationAttribute extends JsonMapperRepresentationAttribute {
  mode: 'complex'
  complex_path?: ComplexAttributePath
}

export interface BasedRepresentationAttribute extends JsonMapperRepresentationAttribute {
  mode: 'base'
  based_on: AttributeBasedOn
}

export type RepresentationAttribute = SimpleRepresentationAttribute | ComplexRepresentationAttribute | BasedRepresentationAttribute;

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
  identifier?: string
  attributes: RepresentationAttribute[]
}

export interface JsonMapperRepresentationResolved {
  id: string
  type: JsonMapperRepresentationType
  target: JsonMapperRepresentationTarget
  attributes: JsonMapperRepresentationAttributeResolved[]
  from?: string
  to?: string
}

export type JsonMapperParsed = Omit<BasicStoreEntityJsonMapper, 'representations' | 'variables'> & {
  variables: { name: string, path: ComplexAttributePath }[]
  representations: JsonMapperRepresentation[]
  user_chosen_markings?: string[]
};

export type JsonMapperResolved = Omit<BasicStoreEntityJsonMapper, 'representations'> & {
  representations: JsonMapperRepresentationResolved[]
  user_chosen_markings?: string[]
};

export interface BasicStoreEntityJsonMapper extends BasicStoreEntity {
  variables: string
  representations: string
  user_chosen_markings?: string[]
}

export interface StoreEntityJsonMapper extends BasicStoreEntityJsonMapper, StoreEntity {}

export interface StixJsonMapper extends StixObject {
  name: string
  representations: string
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
