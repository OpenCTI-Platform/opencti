import { describe, expect, it } from 'vitest';
import { generateKeyValueForIndicator } from '../../../src/domain/stixCyberObservable';

const artifact = {
  _index: 'opencti_stix_cyber_observables-000001',
  _id: '617980fd-9f26-4237-a82d-68e4011de635',
  id: '617980fd-9f26-4237-a82d-68e4011de635',
  sort: [1733914061396],
  internal_id: '617980fd-9f26-4237-a82d-68e4011de635',
  x_opencti_description: 'Artifact uploaded',
  x_opencti_additional_names: [
    '[Content_Types].xml'
  ],
  x_opencti_files: [
    {
      id: 'import/Artifact/617980fd-9f26-4237-a82d-68e4011de635/[Content_Types].xml',
      name: '[Content_Types].xml',
      version: '2024-12-11T10:47:41.374Z',
      mime_type: 'application/xml'
    }
  ],
  mime_type: 'application/xml',
  hashes: {
    MD5: '46c293d9de7b32344e041857515944a6',
    'SHA-1': 'dfe5e1bcc496efac6012e26f013c7b6a6d7c9803',
    'SHA-256': 'bfa02ea1994b73dca866ea3b6596340fe00063d19eab5957c7d8e6a5fa10599a',
    'SHA-512': '0ecf269f1805d6ccc61b247ba7aadd66771b86554509536bb90988b6b0f09521e84167496fd6b9bb3153ae25af6d461c43faae23c75ca4fa050b41d5133a54ba'
  },
  confidence: 100,
  entity_type: 'Artifact',
  standard_id: 'artifact--6fac240c-1af0-5bd3-8176-86d452a1afbb',
  creator_id: ['88ec0c6a-13ce-5e39-b486-354fe4a7084f'],
  x_opencti_stix_ids: [],
  created_at: '2024-12-11T10:47:41.396Z',
  updated_at: '2024-12-11T13:24:12.691Z',
  base_type: 'ENTITY',
  parent_types: [
    'Basic-Object',
    'Stix-Object',
    'Stix-Core-Object',
    'Stix-Cyber-Observable'
  ],
  modified: '2024-12-11T13:24:12.691Z',
};
const file = {
  _index: 'opencti_stix_cyber_observables-000001',
  _id: '28219cea-9995-49bc-9a7a-290170e14806',
  id: '28219cea-9995-49bc-9a7a-290170e14806',
  sort: [
    1733741490002
  ],
  internal_id: '28219cea-9995-49bc-9a7a-290170e14806',
  x_opencti_score: 50,
  x_opencti_description: null,
  hashes: {
    'SHA-256': '057aa4a06395c384a2a9d29f499b410ac1da6fc2c10aa61908eea3e67a32b873',
    'SHA-512': 'c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421'
  },
  name: '',
  name_enc: '',
  magic_number_hex: '',
  mime_type: '',
  ctime: null,
  mtime: null,
  atime: null,
  x_opencti_additional_names: null,
  confidence: 100,
  entity_type: 'StixFile',
  standard_id: 'file--7220cd05-f88f-5dd7-a1ea-e009db45eefb',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_stix_ids: [],
  created_at: '2024-12-09T10:51:30.002Z',
  updated_at: '2024-12-09T10:51:30.002Z',
  base_type: 'ENTITY',
  parent_types: [
    'Basic-Object',
    'Stix-Object',
    'Stix-Core-Object',
    'Stix-Cyber-Observable'
  ]
};

describe('SCO utils', () => {
  it('should generate key value from Artifact with sha256 sha512 sha1 md5', async () => {
    const expectedKey = 'File_sha256__File_sha512__File_sha1__File_md5';
    const expectedValue = 'bfa02ea1994b73dca866ea3b6596340fe00063d19eab5957c7d8e6a5fa10599a__0ecf269f1805d6ccc61b247ba7aadd66771b86554509536bb90988b6b0f09521e84167496fd6b9bb3153ae25af6d461c43faae23c75ca4fa050b41d5133a54ba__dfe5e1bcc496efac6012e26f013c7b6a6d7c9803__46c293d9de7b32344e041857515944a6';
    const { key, value } = generateKeyValueForIndicator('Artifact', artifact.hashes['SHA-512'], artifact);
    expect(key).toEqual(expectedKey);
    expect(value).toEqual(expectedValue);
  });
  it('should generate key value from StixFile with Sha256 and sha512', async () => {
    const expectedKey = 'File_sha256__File_sha512';
    const expectedValue = '057aa4a06395c384a2a9d29f499b410ac1da6fc2c10aa61908eea3e67a32b873__c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421';
    const { key, value } = generateKeyValueForIndicator('StixFile', file.hashes['SHA-512'], file);
    expect(key).toEqual(expectedKey);
    expect(value).toEqual(expectedValue);
  });
});
