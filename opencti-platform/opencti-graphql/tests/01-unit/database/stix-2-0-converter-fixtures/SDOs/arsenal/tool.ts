import type { StoreEntity } from '../../../../../../src/types/store';

export const TOOL_INSTANCE = {
  id: 'c914c155-5672-432d-9904-c7981d81caa5',
  standard_id: 'tool--a8bdbff3-16b4-5cd2-b112-ee7a7b1f359c',
  entity_type: 'Tool',
  name: 'Tool Stix 2.0',
  description: 'description',
  tool_version: '2',
  tool_types: [
    'denial-of-service',
  ],
  created: '2025-08-01T15:23:49.755Z',
  modified: '2025-08-01T15:29:11.399Z',
  confidence: 100,
  revoked: false,
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  killChainPhases: [
    {
      kill_chain_name: 'mitre-pre-attack',
      phase_name: 'launch',
      x_opencti_order: 0,
    },
  ],
  objectMarking: [
    { standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' },
  ],
  createdBy: { standard_id: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024' },
  objectLabel: [{ value: 'ryuk' }],
} as unknown as StoreEntity;

export const EXPECTED_TOOL = {
  id: 'tool--a8bdbff3-16b4-5cd2-b112-ee7a7b1f359c',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-08-01T15:23:49.755Z',
  modified: '2025-08-01T15:29:11.399Z',
  name: 'Tool Stix 2.0',
  description: 'description',
  tool_types: [
    'denial-of-service',
  ],
  tool_version: '2',
  labels: [
    'ryuk',
  ],
  kill_chain_phases: [
    {
      kill_chain_name: 'mitre-pre-attack',
      phase_name: 'launch',
      x_opencti_order: 0,
    },
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  x_opencti_id: 'c914c155-5672-432d-9904-c7981d81caa5',
  x_opencti_type: 'Tool',
  type: 'tool',
  created_by_ref: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
  ],
  x_opencti_files: [],
  x_opencti_granted_refs: [],
};
