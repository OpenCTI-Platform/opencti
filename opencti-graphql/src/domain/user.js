import { assoc, head, isEmpty, mapObjIndexed, values, pipe, last } from 'ramda';
import moment from 'moment';
import bcrypt from 'bcrypt';
import uuid from 'uuid/v4';
import uuidv5 from 'uuid/v5';
import pubsub from '../config/bus';
import driver from '../database/neo4j';
import { FunctionalError, LoginError } from '../config/errors';
import {
  OPENCTI_DEFAULT_DURATION,
  OPENCTI_ISSUER,
  OPENCTI_WEB_TOKEN,
  ROLE_USER,
  USER_ADDED_TOPIC
} from '../config/conf';
import { decrypt, encrypt } from '../config/crypto';

// Security related
export const generateOpenCTIWebToken = email => ({
  id: uuidv5(email, uuidv5.URL),
  name: OPENCTI_WEB_TOKEN,
  created_at: moment().toISOString(),
  issuer: OPENCTI_ISSUER,
  revoked: false,
  duration: OPENCTI_DEFAULT_DURATION // 99 years per default
});

export const hashPassword = password => bcrypt.hash(password, 10);

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
      throw new LoginError();
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
      throw new LoginError();
    }
    const firstRecord = head(data.records);
    const dbUser = firstRecord.get('user');
    const dbPassword = dbUser.properties.password;
    const match = await bcrypt.compare(password, dbPassword);
    if (!match) {
      throw new LoginError();
    }
    return firstRecord.get('token').properties;
  });
};

const pageInfo = (
  startCursor = '',
  endCursor = '',
  hasNextPage = false,
  hasPreviousPage = false
) => ({
  startCursor,
  endCursor,
  hasNextPage,
  hasPreviousPage
});

export const findAll = (first = 25, after = undefined, order = 'id') => {
  const skip = after ? parseInt(decrypt(after), 10) : 0;
  const session = driver.session();
  const query = `MATCH (g:User) WITH count(g) as global MATCH (user:User) RETURN user, global ORDER BY user.${order.toLowerCase()} SKIP {skip} LIMIT {limit}`;
  const promise = session.run(query, {
    skip: skip + 1,
    limit: first
  });
  return promise.then(data => {
    session.close();
    if (isEmpty(data.records)) {
      return { edges: [], pageInfo: pageInfo() };
    }
    // Transform the result to be relay compliant.
    const globalCount = head(data.records).get('global');
    const edges = pipe(
      mapObjIndexed((record, key) => {
        const node = record.get('user').properties;
        const cursor = encrypt(skip + parseInt(key, 10) + 1);
        return { node, cursor };
      }),
      values
    )(data.records);
    const hasNextPage = first + skip < globalCount;
    const hasPreviousPage = skip > 0;
    const startCursor = head(edges).cursor;
    const endCursor = last(edges).cursor;
    const page = pageInfo(startCursor, endCursor, hasNextPage, hasPreviousPage);
    return { edges, pageInfo: page };
  });
};

export const findById = userId => {
  const session = driver.session();
  const promise = session.run('MATCH (user:User {id: {userId}}) RETURN user', {
    userId
  });
  return promise.then(data => {
    session.close();
    if (isEmpty(data.records))
      throw new FunctionalError({ message: 'Cant find this user' });
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
      throw new FunctionalError({ message: "User doesn't exist" });
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
    if (isEmpty(data.records)) return undefined;
    // Token duration validation
    const record = head(data.records);
    const token = record.get('token').properties;
    const creation = moment(token.created_at);
    const maxDuration = moment.duration(token.duration);
    const now = moment();
    const currentDuration = moment.duration(now.diff(creation));
    if (currentDuration > maxDuration) return undefined;
    return record.get('user').properties;
  });
};
