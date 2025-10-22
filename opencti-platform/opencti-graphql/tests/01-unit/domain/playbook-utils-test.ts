import { describe, it, expect } from 'vitest';
import { extractBundleBaseElement } from '../../../src/modules/playbook/playbook-utils';
import type { StixBundle, StixDomainObject } from '../../../src/types/stix-2-1-common';

describe('Function: extractBundleBaseElement()', () => {
  const testBundle: StixBundle = {
    id: '07fbcd58-faef-4eb3-879f-cbdb1cf8c6fe',
    spec_version: '2.1',
    type: 'bundle',
    objects: [
      {
        id: 'malware--f49048d5-6dc8-595d-901d-4bb023a3101f',
        spec_version: '2.1',
        type: 'malware',
      } as unknown as StixDomainObject
    ]
  };

  it('should throw an error if the data is not found in bundle', () => {
    const call = () => extractBundleBaseElement('not-present-id', testBundle);
    expect(call).toThrowError('Playbook base element no longer accessible');
  });

  it('should return data for the given ID', () => {
    const data = extractBundleBaseElement(
      'malware--f49048d5-6dc8-595d-901d-4bb023a3101f',
      testBundle
    );
    expect(data).toEqual({
      id: 'malware--f49048d5-6dc8-595d-901d-4bb023a3101f',
      spec_version: '2.1',
      type: 'malware',
    });
  });
});

describe('Function: convertMembersToUsers()', () => {
  it('should return an empty array if members is empty', () => {});
  it('should return an empty array if no users in cache', () => {});
  it('should return users directly set in members array', () => {});
  it('should return users from a group set in members array', () => {});
  it('should return users from an organization set in members array', () => {});
  it('should replace dynamic key AUTHOR by the correct user', () => {});
  it('should replace dynamic key CREATORS by the correct users', () => {});
  it('should replace dynamic key ASSIGNEES by the correct users', () => {});
  it('should replace dynamic key PARTICIPANTS by the correct users', () => {});
  it('should replace dynamic key BUNDLE_ORGANIZATIONS by the correct users', () => {});
});
