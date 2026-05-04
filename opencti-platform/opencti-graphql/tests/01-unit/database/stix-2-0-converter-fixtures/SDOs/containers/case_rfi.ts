import type { StoreEntityCaseRfi } from '../../../../../../src/modules/case/case-rfi/case-rfi-types';

export const RFI_INSTANCE = {
  id: '4ebd03f2-d922-4449-915e-2facb67e781c',
  standard_id: 'case-rfi--cc1229b2-8ba7-50fd-b822-055b45e3aa4f',
  entity_type: 'Case-Rfi',
  name: 'RFI STIX 2.0',
  description: 'description',
  content: '<p>some content</p>',
  severity: 'medium',
  priority: 'P2',
  confidence: 100,
  created: '2025-06-26T17:50:38.000Z',
  modified: '2025-06-26T17:52:57.246Z',
  revoked: false,
  x_opencti_workflow_id: '38f497dc-b0bc-48e5-aff8-0e5bd5d5937a',
  information_types: ['type 1'],
  x_opencti_files: [
    {
      id: 'import/Case-Rfi/4ebd03f2-d922-4449-915e-2facb67e781c/ipv4_example.json',
      name: 'ipv4_example.json',
      version: '2025-06-26T17:51:30.748Z',
      mime_type: 'application/json',
      objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
    },
  ],
  content_mapping: 'eyJwYXJhZGlzZSByYW5zb213YXJlIjoibWFsd2FyZS0tMjFjNDVkYmUtNTRlYy01YmI3LWI4Y2QtOWYyN2NjNTE4NzE0In0',
  objects: [
    { standard_id: 'campaign--e388a843-1590-5af1-b5a5-50231c97cfba' },
    { standard_id: 'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a' },
    { standard_id: 'incident--8658860d-df08-5f41-bf41-106095e48085' },
    { standard_id: 'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714' },
  ],
  externalReferences: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163',
    },
  ],
  createdBy: { standard_id: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91' },
  objectParticipant: [
    {
      internal_id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      entity_type: 'User',
      base_type: 'ENTITY',
      name: 'marie',
    },
  ],
  objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
  objectAssignee: [
    {
      internal_id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      entity_type: 'User',
      base_type: 'ENTITY',
      name: 'marie',
    },
  ],
  objectLabel: [{ value: 'ryuk' }],
} as unknown as StoreEntityCaseRfi;

export const EXPECTED_RFI = {
  id: 'x-opencti-case-rfi--cc1229b2-8ba7-50fd-b822-055b45e3aa4f',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T17:50:38.000Z',
  modified: '2025-06-26T17:52:57.246Z',
  name: 'RFI STIX 2.0',
  description: 'description',
  information_types: [
    'type 1',
  ],
  severity: 'medium',
  priority: 'P2',
  x_opencti_workflow_id: '38f497dc-b0bc-48e5-aff8-0e5bd5d5937a',
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
  x_opencti_id: '4ebd03f2-d922-4449-915e-2facb67e781c',
  x_opencti_type: 'Case-Rfi',
  type: 'x-opencti-case-rfi',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
  ],
  object_refs: [
    'campaign--e388a843-1590-5af1-b5a5-50231c97cfba',
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a',
    'incident--8658860d-df08-5f41-bf41-106095e48085',
    'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714',
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Case-Rfi/4ebd03f2-d922-4449-915e-2facb67e781c/ipv4_example.json',
      version: '2025-06-26T17:51:30.748Z',
    },
  ],
  x_opencti_granted_refs: [],
};
