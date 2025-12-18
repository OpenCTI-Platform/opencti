import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { DisseminationListAddInput, EditInput } from '../../../src/generated/graphql';
import { addDisseminationList, deleteDisseminationList, fieldPatchDisseminationList } from '../../../src/modules/disseminationList/disseminationList-domain';
import { buildStandardUser, testContext } from '../../utils/testQuery';
import type { StoreEntityDisseminationList } from '../../../src/modules/disseminationList/disseminationList-types';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';

const TEST_DISSEMINATION_USER_SET = buildStandardUser([], [], [{ name: 'SETTINGS_SETDISSEMINATE' }]);
const TEST_DISSEMINATION_LIST_CREATE_INPUT: DisseminationListAddInput = {
  name: 'Dissemination list',
  description: 'Description',
  emails: ['example1@email.com', 'sample.account@email.com', 'firstname.lastname@email.com', 'user123@email.com', 'contact@domain.com', 'info@example.net', 'test.email@email.org', 'random.user@email.co', 'support@email.io', 'myaddress@email.biz'],
};
const TEST_DISSEMINATION_LIST_UPDATE_INPUT: EditInput[] = [
  { key: 'name', value: ['New Dissemination list'] },
  { key: 'description', value: ['New description'] },
  { key: 'emails', value: ['example1@email.com', 'sample.account@email.com'] },
];

describe('Create dissemination list', async () => {
  beforeEach(() => {
    // Activate EE for this test
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
  });
  let data: StoreEntityDisseminationList;

  it('should create a dissemination list for settings user', async () => {
    data = await addDisseminationList(testContext, TEST_DISSEMINATION_USER_SET, TEST_DISSEMINATION_LIST_CREATE_INPUT);
    expect(data.name, 'List created').toBe('Dissemination list');
    expect(data.description, 'List created').toBe('Description');
    expect(data.emails, 'List created').toEqual(['example1@email.com', 'sample.account@email.com', 'firstname.lastname@email.com', 'user123@email.com', 'contact@domain.com', 'info@example.net', 'test.email@email.org', 'random.user@email.co', 'support@email.io', 'myaddress@email.biz']);
  });
  it('should update a dissemination list for settings user', async () => {
    data = await fieldPatchDisseminationList(testContext, TEST_DISSEMINATION_USER_SET, data.id, TEST_DISSEMINATION_LIST_UPDATE_INPUT);
    expect(data.name, 'List updated').toBe('New Dissemination list');
    expect(data.description, 'List updated').toBe('New description');
    expect(data.emails, 'List updated').toEqual(['example1@email.com', 'sample.account@email.com']);
  });
  it('should delete a dissemination list for settings user', async () => {
    const id = await deleteDisseminationList(testContext, TEST_DISSEMINATION_USER_SET, data.id);
    expect(id, 'List deleted').toBe(data.id);
  });
});
