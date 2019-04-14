import { addUser } from '../src/domain/user';

module.exports.up = async next => {
  await addUser(
    {},
    {
      name: 'admin',
      description: '',
      password: 'admin',
      firstname: '',
      lastname: '',
      email: 'admin@opencti.io',
      grant: ['ROLE_ROOT', 'ROLE_ADMIN']
    },
    true
  );
  await addUser(
    {},
    {
      name: 'user',
      description: '',
      password: 'user',
      firstname: '',
      lastname: '',
      email: 'user@opencti.io',
      grant: []
    }
  );
  next();
};

module.exports.down = async next => {
  next();
};
