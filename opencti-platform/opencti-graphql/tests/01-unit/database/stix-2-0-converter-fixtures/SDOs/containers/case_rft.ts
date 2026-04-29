import type { StoreEntityCaseRft } from '../../../../../../src/modules/case/case-rft/case-rft-types';

export const RFT_INSTANCE = {
  id: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
  standard_id: 'case-rft--8456f0c2-0308-578b-b90c-1dd6e0440763',
  entity_type: 'Case-Rft',
  name: 'RFT STIX 2.0',
  description: 'description',
  content: '<p>content: Disco Team Threat Actor Group</p>',
  severity: 'medium',
  priority: 'P2',
  confidence: 100,
  created: '2025-06-26T17:54:43.000Z',
  modified: '2025-06-26T17:56:37.718Z',
  revoked: false,
  takedown_types: ['brand-abuse'],
  x_opencti_files: [
    {
      id: 'import/Case-Rft/ae110ba9-34a7-44ef-86b9-7b52def4b4aa/ipv4_example.json',
      name: 'ipv4_example.json',
      version: '2025-06-26T17:55:28.870Z',
      mime_type: 'application/json',
      objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
    },
  ],
  content_mapping: 'eyJkaXNjbyB0ZWFtIHRocmVhdCBhY3RvciBncm91cCI6InRocmVhdC1hY3Rvci0tZmQ2YjBlNmYtOTZlMC01NjhkLWJhMjQtOGExNDBkMDQyOGNkIn0',
  createdBy: { standard_id: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91' },
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
  objects: [
    { standard_id: 'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a' },
    { standard_id: 'threat-actor--fd6b0e6f-96e0-568d-ba24-8a140d0428cd' },
    { standard_id: 'incident--8658860d-df08-5f41-bf41-106095e48085' },
  ],
  objectParticipant: [
    {
      internal_id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      entity_type: 'User',
      base_type: 'ENTITY',
      name: 'marie',
    },
  ],
  objectLabel: [{ value: 'ryuk' }],
  objectAssignee: [
    {
      internal_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      standard_id: 'user--12ea8141-dc6d-5031-9a1b-c28aeac7198b',
      entity_type: 'User',
      base_type: 'ENTITY',
      name: 'admin',
    },
  ],
} as unknown as StoreEntityCaseRft;

export const EXPECTED_RFT = {
  id: 'x-opencti-case-rft--8456f0c2-0308-578b-b90c-1dd6e0440763',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T17:54:43.000Z',
  modified: '2025-06-26T17:56:37.718Z',
  name: 'RFT STIX 2.0',
  description: 'description',
  takedown_types: [
    'brand-abuse',
  ],
  severity: 'medium',
  priority: 'P2',
  labels: [
    'ryuk',
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  x_opencti_id: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
  x_opencti_type: 'Case-Rft',
  type: 'x-opencti-case-rft',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
  ],
  object_refs: [
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a',
    'threat-actor--fd6b0e6f-96e0-568d-ba24-8a140d0428cd',
    'incident--8658860d-df08-5f41-bf41-106095e48085',
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Case-Rft/ae110ba9-34a7-44ef-86b9-7b52def4b4aa/ipv4_example.json',
      version: '2025-06-26T17:55:28.870Z',
    },
  ],
  x_opencti_granted_refs: [],
};
