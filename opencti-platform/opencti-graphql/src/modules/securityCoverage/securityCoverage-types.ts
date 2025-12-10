import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_SECURITY_COVERAGE = 'Security-Coverage';
export const RELATION_COVERED = 'object-covered';
export const ATTRIBUTE_COVERED = 'covered_ref';
export const INPUT_COVERED = 'objectCovered';

// region Database types
export interface BasicStoreEntitySecurityCoverage extends BasicStoreEntity {
  periodicity: string
  duration: string
  type_affinity: string
  platforms_affinity: string[]
  coverage_information: { coverage_name: string, coverage_score: number }[]
}

export interface StoreEntitySecurityCoverage extends StoreEntity {
  periodicity: string
  duration: string
  type_affinity: string
  platforms_affinity: string[]
  [INPUT_COVERED]: BasicStoreEntity
  coverage_information: { coverage_name: string, coverage_score: number }[]
}
// endregion

// region Stix type
export interface StixSecurityCoverage extends StixDomainObject {
  name: string // optional
  description: string // optional
  periodicity: string
  duration: string
  type_affinity: string
  platforms_affinity: string[]
  covered_ref: string
  covered: boolean
  coverage: { name: string, score: number }[]
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
