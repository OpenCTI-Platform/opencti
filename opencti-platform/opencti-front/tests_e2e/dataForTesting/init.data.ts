import { test } from '../fixtures/baseFixtures';
import { addUsers } from './user.data';
import { addRoles } from './role.data';
import { addGroups } from './group.data';

test('Init data', async ({ request }) => {
  await addRoles(request, [
    {
      name: 'Dashboards',
      capabilities: ['EXPLORE_EXUPDATE_EXDELETE'],
    },
  ]);
  await addGroups(request, [
    {
      name: 'Dashboards group',
      roles: ['Dashboards'],
    },
  ]);
  await addUsers(request, [
    {
      name: 'Jean Michel',
      user_email: 'jean.michel@filigran.test',
      password: 'jeanmichel',
      groups: ['Dashboards group'],
    },
    {
      name: 'Anne',
      user_email: 'anne@filigran.test',
      password: 'anne',
      groups: ['Dashboards group'],
    },
    {
      name: 'Bernadette',
      user_email: 'bernadette@filigran.test',
      password: 'bernadette',
      groups: ['Dashboards group'],
    },
    {
      name: 'Louise',
      user_email: 'louise@filigran.test',
      password: 'louise',
      groups: ['Dashboards group'],
    },
  ]);
});
