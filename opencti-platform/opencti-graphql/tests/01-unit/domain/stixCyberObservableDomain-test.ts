import { describe, expect, it } from 'vitest';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { addStixCyberObservable, generateIndicatorFromObservable, generateKeyValueForIndicator } from '../../../src/domain/stixCyberObservable';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../../src/schema/general';

const artifact = {
  id: '617980fd-9f26-4237-a82d-68e4011de635',
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
  entity_type: 'Artifact',
};
const certificate = {
  _index: 'opencti_stix_cyber_observables-000001',
  _id: '617980fd-9f26-4237-a82d-68e4011de635',
  id: '617980fd-9f26-4237-a82d-68e4011de635',
  name: 'certificateName'
};
const file = {
  id: '28219cea-9995-49bc-9a7a-290170e14806',
  hashes: {
    'SHA-256': '057aa4a06395c384a2a9d29f499b410ac1da6fc2c10aa61908eea3e67a32b873',
    'SHA-512': 'c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421'
  },
  name: '',
  parent_types: [
    'Basic-Object',
    'Stix-Object',
    'Stix-Core-Object',
    'Stix-Cyber-Observable'
  ]
};
const observableWithPid = {
  name: 'observableWithPid',
  pid: 'observablePid'
};
const observableWithSubject = {
  name: 'observableWithSubject',
  subject: 'observableSubject'
};
const observableWithBody = {
  name: 'observableWithBody',
  body: 'observableBody'
};

describe('SCO utils', () => {
  describe('generateKeyValueForIndicator', () => {
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

    it('should generate key value from hashed observable entity type and name', () => {
      const expectedKey = 'X509-Certificate_name';
      const expectedValue = 'certificateName';
      const { key, value } = generateKeyValueForIndicator('X509-Certificate', certificate.name, certificate);
      expect(key).toEqual(expectedKey);
      expect(value).toEqual(expectedValue);
    });

    it('should generate key value from observable with entity type and name', () => {
      const expectedKey = 'Observable_pid';
      const expectedValue = 'observableWithPid';
      const { key, value } = generateKeyValueForIndicator('Observable', observableWithPid.name, observableWithPid);
      expect(key).toEqual(expectedKey);
      expect(value).toEqual(expectedValue);
    });

    it('should generate key value from observable with entity type and subject', () => {
      const expectedKey = 'Observable_subject';
      const expectedValue = 'observableSubject';
      const { key, value } = generateKeyValueForIndicator('Observable', observableWithSubject.name, observableWithSubject);
      expect(key).toEqual(expectedKey);
      expect(value).toEqual(expectedValue);
    });

    it('should generate key value from observable with entity type and body', () => {
      const expectedKey = 'Observable_body';
      const expectedValue = 'observableBody';
      const { key, value } = generateKeyValueForIndicator('Observable', observableWithBody.name, observableWithBody);
      expect(key).toEqual(expectedKey);
      expect(value).toEqual(expectedValue);
    });
  });

  describe('generateIndicatorFromObservable ', () => {
    const observableToGenerateIndicator = {
      entity_type: ABSTRACT_STIX_CYBER_OBSERVABLE,
      name: 'ObservableName'
    };
    const input = {
      createdBy: 'creator',
      objectLabel: [],
      objectMarking: [],
      objectOrganization: [],
      externalReferences: [],
    };

    it('should not be able to generate an indicator because of missing pattern', async () => {
      await expect(() => generateIndicatorFromObservable(testContext, ADMIN_USER, input, observableToGenerateIndicator))
        .rejects.toThrowError('Cannot create indicator - cant generate pattern.');
    });
  });

  describe('addStixCyberObservable', () => {
    it('should not be able to create if the type is not an observable', async () => {
      const input = { type: ENTITY_TYPE_CONTAINER_REPORT };
      await expect(() => addStixCyberObservable(testContext, ADMIN_USER, input))
        .rejects.toThrowError('Observable type Report is not supported.');
    });
  });
});
