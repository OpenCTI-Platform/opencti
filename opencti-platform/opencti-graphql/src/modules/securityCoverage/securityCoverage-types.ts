import type {BasicStoreEntity, StoreEntity} from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_SECURITY_COVERAGE = 'SecurityCoverage';
export const RELATION_ASSESS = 'object-assess';
export const ATTRIBUTE_ASSESS = 'assess_ref';
export const INPUT_ASSESS = 'objectAssess';

// region Database types
export interface StoreEntitySecurityCoverage extends StoreEntity {
  periodicity: string
  [INPUT_ASSESS]: BasicStoreEntity
  coverage: { name: string, score: number }[]
}
// endregion

// region Stix type
export interface StixSecurityCoverage extends StixDomainObject {
  name: string // optional
  description: string // optional
  periodicity: string
  assess_ref: string
  coverage: { name: string, score: number }[]
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
