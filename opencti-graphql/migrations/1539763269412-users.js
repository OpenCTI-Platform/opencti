import { addUser, deleteUser } from '../src/domain/user';

module.exports.up = async next => {
  await addUser({
    id: 'a1f062c4-e0de-4906-82b5-e047ca50dea4',
    username: 'Julien',
    password: 'julien',
    email: 'richard.julien@gmail.com',
    roles: ['ROLE_ADMIN']
  });
  await addUser({
    id: '52d714f5-aa55-4502-8d9c-012a049bc7d7',
    username: 'Samuel Hassine',
    password: 'samuel',
    email: 'samuel.hassine@gmail.com',
    roles: ['ROLE_ADMIN']
  });
  next();
};

module.exports.down = async next => {
  await deleteUser('a1f062c4-e0de-4906-82b5-e047ca50dea4');
  await deleteUser('52d714f5-aa55-4502-8d9c-012a049bc7d7');
  next();
};
