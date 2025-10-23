import { describe, it, expect } from 'vitest';
import { convertMembersToUsers, extractBundleBaseElement } from '../../../src/modules/playbook/playbook-utils';
import type { StixBundle, StixDomainObject } from '../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

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
  const testBundle: StixBundle = {
    id: '07fbcd58-faef-4eb3-879f-cbdb1cf8c6fe',
    spec_version: '2.1',
    type: 'bundle',
    objects: [
      {
        id: 'malware--f49048d5-6dc8-595d-901d-4bb023a3101f',
        spec_version: '2.1',
        type: 'malware',
        extensions: {
          [STIX_EXT_OCTI]: {
            created_by_ref_id: '5072fe4b-aec3-4f4d-9902-2231b34f4429',
            creator_ids: [
              '1f56e76f-2538-4549-8270-78db61f84ba1',
              'da4668b4-6971-4134-b2aa-e3b9c854ae29'
            ],
            assignee_ids: [
              'cff2b484-ba42-4f91-9a21-96a839a86372'
            ],
            participant_ids: [
              '6144a129-829d-4b5f-a3c0-01320c956994',
              '5072fe4b-aec3-4f4d-9902-2231b34f4429',
            ]
          }
        }
      } as unknown as StixDomainObject
    ]
  };
  const baseData = testBundle.objects[0];

  it('should return an empty array if members is empty', async () => {
    expect(await convertMembersToUsers([], baseData, testBundle)).toEqual([]);
  });

  it('should return users directly set in members array', async () => {
    const members = [
      { value: 'invalid_id' },
      // ID of user admin.
      { value: '88ec0c6a-13ce-5e39-b486-354fe4a7084f' },
    ];
    const users = await convertMembersToUsers(members, baseData, testBundle);
    const usersNames = users.map((u) => u.name);
    expect(usersNames).toEqual(['admin']);
  });

  it('should return users from a group set in members array', async () => {
    const members = [
      { value: 'invalid_id' },
      // ID of group GREEN GROUP.
      { value: 'fae90eec-2c99-4deb-b940-3de425669b48' },
    ];
    const users = await convertMembersToUsers(members, baseData, testBundle);
    const usersNames = users.map((u) => u.name);
    expect(usersNames).toEqual(['participate@opencti.io']);
  });

  it('should return users from an organization set in members array', async () => {
    const members = [
      { value: 'invalid_id' },
      // ID of organization PlatformOrganization.
      { value: 'f8738103-c5fb-4ae2-8aeb-a687a0678405' },
    ];
    const users = await convertMembersToUsers(members, baseData, testBundle);
    const usersNames = users.map((u) => u.name);
    expect(usersNames).toEqual(['anais@opencti.io', 'security@opencti.io']);
  });

  it('should replace dynamic key AUTHOR by the correct user', async () => {
    const members = [
      { value: 'invalid_id' },
      { value: 'AUTHOR' },
    ];
    const users = await convertMembersToUsers(members, baseData, testBundle);
    const usersNames = users.map((u) => u.name);
    expect(usersNames).toEqual(['connector@opencti.io']);
  });

  it('should replace dynamic key CREATORS by the correct users', async () => {
    const members = [
      { value: 'invalid_id' },
      { value: 'CREATORS' },
    ];
    const users = await convertMembersToUsers(members, baseData, testBundle);
    const usersNames = users.map((u) => u.name);
    expect(usersNames).toEqual(['platform@opencti.io', 'security@opencti.io']);
  });

  it('should replace dynamic key ASSIGNEES by the correct users', async () => {
    const members = [
      { value: 'invalid_id' },
      { value: 'ASSIGNEES' },
    ];
    const users = await convertMembersToUsers(members, baseData, testBundle);
    const usersNames = users.map((u) => u.name);
    expect(usersNames).toEqual(['editor@opencti.io']);
  });

  it('should replace dynamic key PARTICIPANTS by the correct users', async () => {
    const members = [
      { value: 'invalid_id' },
      { value: 'PARTICIPANTS' },
    ];
    const users = await convertMembersToUsers(members, baseData, testBundle);
    const usersNames = users.map((u) => u.name);
    expect(usersNames).toEqual(['anais@opencti.io', 'connector@opencti.io']);
  });
});
