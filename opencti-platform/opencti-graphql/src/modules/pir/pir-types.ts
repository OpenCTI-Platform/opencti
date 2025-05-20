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
  pirCriteria: PirCriterion[]
  pirFilters: string
  lastEventId: string
}

export interface StoreEntityPir extends StoreEntity {
  name: string
  pirCriteria: PirCriterion[]
  pirFilters: string
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
  // Criteria are filters with a weight,
  // they are used to compute matching score.
  pirCriteria: ParsedPirCriterion[]
  // Filters do not count when computing score, their role
  // is to exclude some data (low confidence for example).
  pirFilters: FilterGroup
}

export interface PirDependency {
  relationship_id: string,
  criterion: PirCriterion,
}

export interface BasicStoreRelationPir extends BasicStoreRelation {
  pir_dependencies: PirDependency[],
}
