import type { StoreEntitySecurityCoverage } from '../../../../../../src/modules/securityCoverage/securityCoverage-types';

export const SECURITY_COVERAGE_INSTANCE = {
  id: '6f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0',
  standard_id: 'security-coverage--8e2f1a3b-4c5d-5e6f-8a7b-9c0d1e2f3a4b',
  entity_type: 'Security-Coverage',
  created: '2026-03-18T10:04:59.276Z',
  modified: '2026-03-18T10:24:35.407Z',
  confidence: 100,
  revoked: false,
  name: 'Coverage of APT28',
  description: 'description',
  periodicity: 'P1D',
  duration: 'PT1H',
  type_affinity: 'ENDPOINT',
  platforms_affinity: ['windows', 'linux'],
  external_uri: 'https://openaev.example.com/scenarios/1',
  auto_enrichment_disable: true,
  coverage_last_result: '2026-03-18T09:00:00.000Z',
  coverage_information: [
    { coverage_name: 'PREVENTION', coverage_score: 60 },
    { coverage_name: 'DETECTION', coverage_score: 80 },
  ],
  objectCovered: { standard_id: 'intrusion-set--738e5ee3-6781-5f4c-93b0-d914bbf0c1d3' },
  resultOf: [{ standard_id: 'security-coverage-result--1b2c3d4e-5f60-5a7b-8c9d-0e1f2a3b4c5d' }],
  createdBy: { standard_id: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb' },
  objectLabel: [{ value: 'stix 2.0' }],
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
} as unknown as StoreEntitySecurityCoverage;

// Not output: `auto_enrichment_disable`, the results, and the properties that
// the API computes from the results: `external_uri` (stored on old coverages
// only), `coverage_last_result` and the coverage information.
export const EXPECTED_SECURITY_COVERAGE = {
  id: 'security-coverage--8e2f1a3b-4c5d-5e6f-8a7b-9c0d1e2f3a4b',
  type: 'security-coverage',
  spec_version: '2.0',
  x_opencti_id: '6f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0',
  x_opencti_type: 'Security-Coverage',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  created: '2026-03-18T10:04:59.276Z',
  modified: '2026-03-18T10:24:35.407Z',
  revoked: false,
  confidence: 100,
  labels: ['stix 2.0'],
  object_marking_refs: ['marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'],
  created_by_ref: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb',
  external_references: [],
  name: 'Coverage of APT28',
  description: 'description',
  periodicity: 'P1D',
  duration: 'PT1H',
  type_affinity: 'ENDPOINT',
  platforms_affinity: ['windows', 'linux'],
  covered_ref: 'intrusion-set--738e5ee3-6781-5f4c-93b0-d914bbf0c1d3',
};
