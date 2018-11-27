import { addUser, deleteUser } from '../src/domain/user';

module.exports.up = async next => {
  await addUser({
    username: 'admin',
    password: 'admin',
    email: 'admin@opencti.org',
    grant: ['ROLE_ADMIN']
  });
  await addUser({
    username: 'user',
    password: 'user',
    email: 'user@opencti.org',
    grant: ['ROLE_USER']
  });
  next();
};

module.exports.down = async next => {
  await deleteUser('admin@opencti.org');
  await deleteUser('user@opencti.org');
  next();
};
