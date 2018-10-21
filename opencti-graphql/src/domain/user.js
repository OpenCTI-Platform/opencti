import { assoc, pipe, contains, head, isEmpty, map } from 'ramda';
import moment from 'moment';
import bcrypt from 'bcrypt';
import uuid from 'uuid/v4';
import uuidv5 from 'uuid/v5';
import pubsub from '../config/bus';
import driver from '../database/index';

export const USER_ADDED_TOPIC = 'USER_ADDED_TOPIC';
const OPENCTI_WEB_TOKEN = 'Default';
const ROLE_USER = 'ROLE_USER';
const ROLE_ADMIN = 'ROLE_ADMIN';

// Security related
export const assertUserRole = (user, role) => {
  if (!contains(role, user.roles)) throw new Error('Insufficient privilege');
};

const generateOpenCTIWebToken = email => ({
  id: uuidv5(email, uuidv5.URL),
  name: OPENCTI_WEB_TOKEN,
  created_at: moment().toISOString(),
  issuer: 'OpenCTI',
  revoked: false,
  duration: 'P99Y' // 99 years per default
});

export const hashPassword = password => bcrypt.hash(password, 10);

export const assertAdmin = user => {
  assertUserRole(user, ROLE_ADMIN);
};

// User related
export const loginFromProvider = (email, username) => {
  const session = driver.session();
  const user = {
    id: uuid(),
    username,
    email,
    roles: [ROLE_USER],
    created_at: moment().toISOString(),
    password: null
  };
  const token = generateOpenCTIWebToken(email);
  const promise = session.run(
    'MERGE (user:User {email: {user}.email}) ON CREATE SET user = {user} ' +
      'MERGE (user)<-[:WEB_ACCESS]-(token:Token {name: {token}.name}) ON CREATE SET token = {token} ' +
      'RETURN token',
    { user, token }
  );
  return promise.then(async data => {
    session.close();
    if (isEmpty(data.records)) {
      throw new Error('login failed');
    }
    return head(data.records).get('token').properties;
  });
};

export const login = (email, password) => {
  const session = driver.session();
  const promise = session.run(
    'MATCH (user:User {email: {email}})<-[:WEB_ACCESS]-(token:Token) RETURN user, token',
    { email }
  );
  return promise.then(async data => {
    session.close();
    if (isEmpty(data.records)) {
      throw new Error('login failed');
    }
    const firstRecord = head(data.records);
    const dbUser = firstRecord.get('user');
    const dbPassword = dbUser.properties.password;
    const match = await bcrypt.compare(password, dbPassword);
    if (!match) {
      throw new Error('login failed');
    }
    return firstRecord.get('token').properties;
  });
};

export const findAll = (first, offset) => {
  const session = driver.session();
  const promise = session.run(
    'MATCH (user:User) RETURN user ORDER BY user.id SKIP {skip} LIMIT {limit}',
    { skip: offset, limit: first }
  );
  return promise.then(data => {
    session.close();
    return map(record => record.get('user').properties, data.records);
  });
};

export const findById = userId => {
  const session = driver.session();
  const promise = session.run('MATCH (user:User {id: {userId}}) RETURN user', {
    userId
  });
  return promise.then(data => {
    session.close();
    if (isEmpty(data.records)) throw new Error('Cant find this user');
    return head(data.records).get('user').properties;
  });
};

export const addUser = async user => {
  const completeUser = pipe(
    assoc('created_at', moment().toISOString()),
    assoc('password', await hashPassword(user.password))
  )(user);
  const session = driver.session();
  const promise = session.run(
    'CREATE (user:User {user})<-[:WEB_ACCESS]-(token:Token {token}) RETURN user',
    { user: completeUser, token: generateOpenCTIWebToken(user.email) }
  );
  return promise.then(data => {
    session.close();
    const userAdded = head(data.records).get('user').properties;
    pubsub.publish(USER_ADDED_TOPIC, { userAdded });
    return userAdded;
  });
};

export const deleteUser = userId => {
  const session = driver.session();
  const promise = session.run(
    'MATCH (user:User {id: {userId}}) DELETE user RETURN user',
    { userId }
  );
  return promise.then(data => {
    session.close();
    if (isEmpty(data.records)) {
      throw new Error("User doesn't exist");
    } else {
      return userId;
    }
  });
};

// Token related
export const findByTokenId = tokenId => {
  const session = driver.session();
  // Fetch user by token relation if the token is not revoked
  const promise = session.run(
    'MATCH (token:Token {id: {tokenId}, revoked: false})-->(user) RETURN user, token',
    { tokenId }
  );
  return promise.then(data => {
    session.close();
    if (isEmpty(data.records))
      throw new Error(`User token invalid: ${tokenId}`);
    // Token duration validation
    const record = head(data.records);
    const token = record.get('token').properties;
    const creation = moment(token.created_at);
    const maxDuration = moment.duration(token.duration);
    const now = moment();
    const currentDuration = moment.duration(now.diff(creation));
    if (currentDuration > maxDuration)
      throw new Error(`User token invalid: ${tokenId}`);
    return record.get('user').properties;
  });
};
