import { addUser, deleteUserByEmail } from '../src/domain/user';

module.exports.up = async next => {
  await addUser(
    {},
    {
      name: 'admin',
      password: 'admin',
      firstname: '',
      lastname: '',
      email: 'admin@opencti.org',
      grant: ['ROLE_ADMIN']
    }
  );
  await addUser(
    {},
    {
      name: 'user',
      password: 'user',
      firstname: '',
      lastname: '',
      email: 'user@opencti.org',
      grant: ['ROLE_USER']
    }
  );
  next();
};

module.exports.down = async next => {
  await deleteUserByEmail('admin@opencti.org');
  await deleteUserByEmail('user@opencti.org');
  next();
};
