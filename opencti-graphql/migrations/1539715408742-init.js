import { addUser, deleteUser } from '../src/domain/user';

module.exports.up = async next => {
  await addUser({
    id: '507cccf1-9937-441f-a0ae-22c98ec6ed5b',
    username: 'admin',
    password: 'admin',
    email: 'admin@opencti.org',
    roles: ['ROLE_ADMIN']
  });
  await addUser({
    id: 'ebb7bbfa-fee4-4540-8883-5d98aca7fc02',
    username: 'user',
    password: 'user',
    email: 'user@opencti.org',
    roles: ['ROLE_USER']
  });
  await addUser({
    id: 'a1f062c4-e0de-4906-82b5-e047ca50dea4',
    username: 'Julien',
    password: 'julien',
    email: 'richard.julien@gmail.com',
    roles: ['ROLE_ADMIN']
  });
  next();
};

module.exports.down = async next => {
  await deleteUser('507cccf1-9937-441f-a0ae-22c98ec6ed5b');
  await deleteUser('ebb7bbfa-fee4-4540-8883-5d98aca7fc02');
  await deleteUser('a1f062c4-e0de-4906-82b5-e047ca50dea4');
  next();
};
