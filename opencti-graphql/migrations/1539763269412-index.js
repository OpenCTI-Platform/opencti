
import {driver} from "../src/database";

const createUserIndex = () => {
    let session = driver.session();
    let promise = session.run('CREATE CONSTRAINT ON (user:User) ASSERT user.email IS UNIQUE');
    return promise.then(() => {
        session.close();
    });
};

const deleteUserIndex = () => {
    let session = driver.session();
    let promise = session.run('DROP CONSTRAINT ON (user:User) ASSERT exists(user.email)');
    return promise.then(() => {
        session.close();
    });
};

module.exports.up = async function (next) {
  await createUserIndex();
  next()
};

module.exports.down = async function (next) {
  await deleteUserIndex();
  next()
};
