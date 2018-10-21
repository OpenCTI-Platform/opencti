import driver from '../src/database/neo4j';

const createUserIndex = () => {
  const session = driver.session();
  const promise = session.run(
    'CREATE CONSTRAINT ON (user:User) ASSERT user.email IS UNIQUE'
  );
  return promise.then(() => {
    session.close();
  });
};

const deleteUserIndex = () => {
  const session = driver.session();
  const promise = session.run(
    'DROP CONSTRAINT ON (user:User) ASSERT exists(user.email)'
  );
  return promise.then(() => {
    session.close();
  });
};

module.exports.up = async next => {
  await createUserIndex();
  next();
};

module.exports.down = async next => {
  await deleteUserIndex();
  next();
};
