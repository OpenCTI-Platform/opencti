import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import type { BasicStoreEntitySecurityCoverage } from '../securityCoverage-types';

export const ENTITY_TYPE_SECURITY_COVERAGE_RESULT = 'Security-Coverage-Result';
export const RELATION_RESULT_OF = 'result-of';
export const ATTRIBUTE_RESULT_OF = 'result_of_ref';
export const INPUT_RESULT_OF = 'resultOf';

interface CoverageInformation {
  coverage_name: string;
  coverage_score: number;
}

export interface BasicStoreEntitySecurityCoverageResult extends BasicStoreEntity {
  name: string;
  external_uri?: string;
  coverage_last_result?: string;
  coverage_valid_from?: string;
  coverage_valid_to?: string;
  coverage_information?: CoverageInformation[];
}

export interface StoreEntitySecurityCoverageResult extends StoreEntity {
  name: string;
  external_uri?: string;
  coverage_last_result?: string;
  coverage_valid_from?: string;
  coverage_valid_to?: string;
  coverage_information?: CoverageInformation[];
  [INPUT_RESULT_OF]: BasicStoreEntitySecurityCoverage;
}

export interface StixSecurityCoverageResult extends StixDomainObject {
  name: string;
  external_uri?: string;
  coverage_last_result?: string;
  coverage_valid_from?: string;
  coverage_valid_to?: string;
  coverage: { name: string; score: number }[];
  covered: boolean;
  [ATTRIBUTE_RESULT_OF]: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
