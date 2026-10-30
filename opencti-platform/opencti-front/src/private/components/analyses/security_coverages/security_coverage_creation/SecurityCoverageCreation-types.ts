import { FieldOption } from 'src/utils/field';
import { CoverageInformation } from '../SecurityCoverage-types';
import { StixCoreRelationshipCreationAddInput } from '../../../common/stix_core_relationships/StixCoreRelationshipCreation';

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
  filters?: string;
  excluded_ids?: string[];
  search?: string;
  relationships_config?: StixCoreRelationshipCreationAddInput;
}

export const HAS_COVERED_TARGETS_TYPES = ['Attack-Pattern', 'Vulnerability', 'Artifact', 'Indicator', 'SecurityPlatform'];
