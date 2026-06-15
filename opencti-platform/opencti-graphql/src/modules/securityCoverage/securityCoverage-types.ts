import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { ATTRIBUTE_RESULT_OF, BasicStoreEntitySecurityCoverageResult, INPUT_RESULT_OF, RELATION_RESULT_OF } from './securityCoverageResult/securityCoverageResult-types';

export const ENTITY_TYPE_SECURITY_COVERAGE = 'Security-Coverage';
export const RELATION_COVERED = 'object-covered';
export const ATTRIBUTE_COVERED = 'covered_ref';
export const INPUT_COVERED = 'objectCovered';

// region Database types
export interface BasicStoreEntitySecurityCoverage extends BasicStoreEntity {
  periodicity: string;
  duration: string;
  type_affinity: string;
  platforms_affinity: string[];
  [RELATION_COVERED]: string;
  [RELATION_RESULT_OF]: string[];
}

export interface StoreEntitySecurityCoverage extends StoreEntity {
  periodicity: string;
  duration: string;
  type_affinity: string;
  platforms_affinity: string[];
  [INPUT_COVERED]: BasicStoreEntity;
  [INPUT_RESULT_OF]: BasicStoreEntitySecurityCoverageResult[];
}
// endregion

// region Stix type
export interface StixSecurityCoverage extends StixDomainObject {
  name: string; // optional
  description: string; // optional
  periodicity: string;
  duration: string;
  type_affinity: string;
  platforms_affinity: string[];
  [ATTRIBUTE_COVERED]: string;
  [ATTRIBUTE_RESULT_OF]: string[];
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
