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

import type { BasicStoreEntity, BasicStoreRelation, StoreEntity, StoreRelation } from '../../types/store';
import type { StixInternal } from '../../types/stix-2-1-common';
import { type FilterGroup, PirType } from '../../generated/graphql';
import type { AuthorizedMember } from '../../utils/access';

export const ENTITY_TYPE_PIR = 'Pir';
export const PIR_TYPES = Object.values(PirType);

export interface PirCriterion {
  filters: string
  weight: number
}

export interface BasicStoreEntityPir extends BasicStoreEntity {
  name: string
  pir_type: PirType
  description: string
  pir_rescan_days: number
  pir_criteria: PirCriterion[]
  pir_filters: string
  lastEventId: string
  restricted_members: Array<AuthorizedMember>;
}

export interface StoreEntityPir extends StoreEntity {
  name: string
  pir_type: PirType
  description: string
  pir_rescan_days: number
  pir_criteria: PirCriterion[]
  pir_filters: string
  lastEventId: string
  restricted_members: Array<AuthorizedMember>;
}

export interface StixPir extends StixInternal {
  name: string
}

export interface ParsedPirCriterion {
  filters: FilterGroup
  weight: number
}

export interface ParsedPir {
  id: string
  name: string
  pir_type: PirType
  description: string
  pir_rescan_days: number
  // Criteria are filters with a weight,
  // they are used to compute matching score.
  pir_criteria: ParsedPirCriterion[]
  // Filters do not count when computing score, their role
  // is to exclude some data (low confidence for example).
  pir_filters: FilterGroup
}

interface PirDependency {
  element_id: string,
  author_id?: string | null,
}

export interface PirExplanation {
  dependencies: PirDependency[],
  criterion: PirCriterion,
}

export interface BasicStoreRelationPir extends BasicStoreRelation {
  pir_explanation: PirExplanation[],
  pir_score: number,
  authorized_authorities: string[],
}

export interface StoreRelationPir extends StoreRelation, BasicStoreRelationPir {
}
