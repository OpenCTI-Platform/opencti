import { addUser, deletUserByEmail } from '../src/domain/user';

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
  await deletUserByEmail('admin@opencti.org');
  await deletUserByEmail('user@opencti.org');
  next();
};
