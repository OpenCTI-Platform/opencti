// Type definitions for GraphQL responses
export interface StixCoreObjectNode {
  id: string;
  name?: string;
  entity_type: string;
  created_at: string;
  representative?: { main: string };
  createdBy?: { id: string; name: string };
  objectLabel?: { id: string; value: string; color: string }[];
  objectMarking?: { id: string; definition_type: string; definition: string; x_opencti_order: number; x_opencti_color: string }[];
}

export enum StepKey {
  MODE = 'mode',
  OBJECT_COVERED = 'objectCovered',
  COMPATIBLE_ENTITIES = 'compatibleEntities',
  COVERAGE_DETAILS = 'coverageDetails',
}

export enum SecurityCoverageMode {
  MANUAL = 'manual',
  AUTO = 'automated',
}
