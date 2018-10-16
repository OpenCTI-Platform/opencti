import {addUser, deleteUser} from '../src/domain/user';

module.exports.up = async function (next) {
    await addUser({
        id: '507cccf1-9937-441f-a0ae-22c98ec6ed5b',
        username: 'julien', password: 'julien',
        email: 'richard.julien@gmail.com', roles: ['ROLE_ADMIN', 'ROLE_USER']
    });
    await addUser({
        id: 'ebb7bbfa-fee4-4540-8883-5d98aca7fc02',
        username: 'sam', password: 'sam',
        email: 'samuel.hassine@gmail.com', roles: ['ROLE_ADMIN', 'ROLE_USER']
    });
    next();
};

module.exports.down = async function (next) {
    await deleteUser('507cccf1-9937-441f-a0ae-22c98ec6ed5b');
    await deleteUser('ebb7bbfa-fee4-4540-8883-5d98aca7fc02');
    next()
};
