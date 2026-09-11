import { FieldOption } from 'src/utils/field';
import { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import { CoverageInformation } from '../SecurityCoverage-types';

export enum StepKey {
  MODE = 'mode',
  OBJECT_COVERED = 'objectCovered',
  TESTED_ENTITIES = 'testedEntities',
  COVERAGE_DETAILS = 'coverageDetails',
}

export enum SecurityCoverageMode {
  MANUAL = 'manual',
  AUTO = 'automated',
}

export interface SecurityCoverageFormValues {
  name: string;
  description: string;
  external_uri: string;
  auto_enrichment_disable: boolean;
  confidence: number | undefined;
  createdBy?: FieldOption;
  objectMarking: { value: string }[];
  objectLabel: { value: string; label: string }[];
  coverage_information: CoverageInformation[];
  periodicity?: string;
  duration?: string;
  type_affinity: 'ENDPOINT';
  platforms_affinity: string[];
}

export interface SelectedEntities {
  selected_ids?: string[];
  filters?: FilterGroup;
  excluded_ids?: string[];
  search?: string;
}

export const HAS_COVERED_TARGETS_TYPES = ['Attack-Pattern', 'Vulnerability', 'Artifact', 'Indicator', 'SecurityPlatform'];
