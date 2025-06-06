import type { BasicStoreEntity, BasicStoreRelation, StoreEntity } from '../../types/store';
import type { StixInternal } from '../../types/stix-2-1-common';
import type { FilterGroup } from '../../generated/graphql';

export const ENTITY_TYPE_PIR = 'Pir';

export interface PirCriterion {
  filters: string
  weight: number
}

export interface BasicStoreEntityPir extends BasicStoreEntity {
  name: string
  description: string
  pir_rescan_days: number
  pir_criteria: PirCriterion[]
  pir_filters: string
  lastEventId: string
}

export interface StoreEntityPir extends StoreEntity {
  name: string
  description: string
  pir_rescan_days: number
  pir_criteria: PirCriterion[]
  pir_filters: string
  lastEventId: string
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
  author_id: string,
}

export interface PirExplanation {
  dependencies: PirDependency[],
  criterion: PirCriterion,
}

export interface BasicStoreRelationPir extends BasicStoreRelation {
  pir_explanations: PirExplanation[],
}
