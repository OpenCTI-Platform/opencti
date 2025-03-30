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

export type JsonMapperParsed = Omit<BasicStoreEntityJsonMapper, 'representations' | 'variables'> & {
  variables: { name: string, path: ComplexPath }[]
  representations: JsonMapperRepresentation[]
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
