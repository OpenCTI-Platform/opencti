import { addUser, deletUserByEmail } from '../src/domain/user';

module.exports.up = async next => {
  await addUser({
    username: 'Julien',
    password: 'julien',
    email: 'richard.julien@gmail.com',
    grant: ['ROLE_ROOT', 'ROLE_ADMIN']
  });
  await addUser({
    username: 'Samuel Hassine',
    password: 'samuel',
    email: 'samuel.hassine@gmail.com',
    grant: ['ROLE_ROOT', 'ROLE_ADMIN']
  });
  next();
};

module.exports.down = async next => {
  await deletUserByEmail('richard.julien@gmail.com');
  await deletUserByEmail('samuel.hassine@gmail.com');
  next();
};
