import { test } from '../fixtures/baseFixtures';
import { addUsers } from './user.data';

test('Init data', async ({ request }) => {
  await addUsers(request, [
    {
      name: 'Jean Michel',
      user_email: 'jean.michel@filigran.test',
      password: 'jeanmichel',
    },
    {
      name: 'Anne',
      user_email: 'anne@filigran.test',
      password: 'anne',
    },
    {
      name: 'Bernadette',
      user_email: 'bernadette@filigran.test',
      password: 'bernadette',
    },
    {
      name: 'Louise',
      user_email: 'louise@filigran.test',
      password: 'louise',
    },
  ]);
});
