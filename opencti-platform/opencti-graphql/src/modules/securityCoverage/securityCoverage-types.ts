import type { BasicIdentityEntity, StoreEntityIdentity } from '../../types/store';
import type { StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixContainer } from '../../types/stix-2-1-sdo';

export const ENTITY_TYPE_SECURITY_COVERAGE = 'SecurityCoverage';
export const RELATION_ASSESS = 'object-assess';
export const ATTRIBUTE_ASSESS = 'assess_ref';
export const INPUT_ASSESS = 'objectAssess';

// region Database types
export interface BasicStoreEntitySecurityCoverage extends BasicIdentityEntity {
  security_platform_type: string
}

export interface StoreEntitySecurityCoverage extends StoreEntityIdentity, BasicStoreEntitySecurityCoverage {
  filters: string
  periodicity: string
  latest_coverage: { name: string, score: number }[]
}
// endregion

// region Stix type
export interface StixSecurityCoverage extends StixContainer {
  name: string // optional
  description: string // optional
  filters: string
  periodicity: string
  latest_coverage: { name: string, score: number }[]
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
