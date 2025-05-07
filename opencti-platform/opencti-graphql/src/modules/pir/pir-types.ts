import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixInternal } from '../../types/stix-2-1-common';
import type { FilterGroup } from '../../generated/graphql';

export const ENTITY_TYPE_PIR = 'PIR';

export interface PIRCriterion {
  id: string
  filters: string
  weight: number
}

export interface BasicStoreEntityPIR extends BasicStoreEntity {
  name: string
  pirCriteria: PIRCriterion[]
  pirFilters: string
  lastEventId: string
}

export interface StoreEntityPIR extends StoreEntity {
  name: string
  pirCriteria: PIRCriterion[]
  pirFilters: string
}

export interface StixPIR extends StixInternal {
  name: string
}

export interface ParsedPIRCriterion {
  id: string
  filters: FilterGroup
  weight: number
}

export interface ParsedPIR {
  id: string
  name: string
  // Criteria are filters with a weight,
  // they are used to compute matching score.
  pirCriteria: ParsedPIRCriterion[]
  // Filters do not count when computing score, their role
  // is to exclude some data (low confidence for example).
  pirFilters: FilterGroup
  lastEventId: string
}

export interface PirDependency {
  relationship_id: string,
  criterion: PIRCriterion,
}
