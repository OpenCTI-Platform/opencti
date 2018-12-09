import { head, isEmpty, join, map } from 'ramda';
import uuidv5 from 'uuid/v5';
import moment from 'moment';
import bcrypt from 'bcrypt';
import { sign } from 'jsonwebtoken';
import { delEditContext, pubsub, setEditContext } from '../database/redis';
import { FunctionalError, LoginError } from '../config/errors';
import conf, {
  BUS_TOPICS,
  DEV_MODE,
  OPENCTI_DEFAULT_DURATION,
  OPENCTI_ISSUER,
  OPENCTI_WEB_TOKEN,
  ROLE_USER
} from '../config/conf';
import {
  createRelation,
  deleteByID,
  editInputTx,
  loadByID,
  notify,
  now,
  paginate,
  qk
} from '../database/grakn';

// Security related
export const generateOpenCTIWebToken = email => ({
  uuid: uuidv5(email, uuidv5.URL),
  name: OPENCTI_WEB_TOKEN,
  created: now(),
  issuer: OPENCTI_ISSUER,
  revoked: false,
  duration: OPENCTI_DEFAULT_DURATION // 99 years per default
});

export const setAuthenticationCookie = (token, res) => {
  const creation = moment(token.created);
  const maxDuration = moment.duration(token.duration);
  const expires = creation.add(maxDuration).toDate();
  const signedToken = sign(token, conf.get('jwt:secret'));
  res.cookie('opencti_token', signedToken, {
    httpOnly: false,
    expires,
    secure: !DEV_MODE
  });
};

export const hashPassword = password => bcrypt.hash(password, 10);

export const addUser = async user => {
  const userPassword = await hashPassword(user.password);
  const token = generateOpenCTIWebToken(user.email);
  const createUser = qk(`insert $x isa User 
    has username "${user.username}";
    $x has email "${user.email}";
    $x has created ${now()};
    $x has password "${userPassword}";
    ${join(' ', map(role => `$x has grant "${role}";`, user.grant))}
  `);
  const createToken = qk(`insert $x isa Token 
    has uuid "${token.uuid}";
    $x has name "${token.name}";
    $x has created ${token.created};
    $x has issuer "${token.issuer}";
    $x has revoked ${token.revoked};
    $x has duration "${token.duration}";
  `);
  // Execute user and token creation in parrallel, then create the relation.
  Promise.all([createUser, createToken]).then(() =>
    // Create the relation
    qk(`match $user isa User has email "${user.email}"; 
                   $token isa Token has uuid "${token.uuid}"; 
                   insert (client: $user, authorization: $token) isa authorize;`).then(
      () => {
        pubsub.publish(BUS_TOPICS.User.ADDED_TOPIC, { user });
        return user;
      }
    )
  );
};

// User related
export const loginFromProvider = (email, username) => {
  // Try to get the user.
  const loginPromise = qk(`match $client isa User has email "${email}";
      $client has password $password;
      (authorization:$token, client:$client); 
      get;`);
  return loginPromise.then(result => {
    const { data } = result;
    if (isEmpty(data)) {
      // We need to create the user because we trust the provider
      const user = {
        username,
        email,
        grant: [ROLE_USER],
        created: now(),
        password: null
      };
      // Create the user then restart the login
      return addUser(user).then(() => loginFromProvider(email, username));
    }
    // We just need to return the current token
    const element = head(data);
    return loadByID(element.token.id);
  });
};

export const login = (email, password) => {
  const loginPromise = qk(`match $client isa User has email "${email}";
      $client has password $password;
      (authorization:$token, client:$client); 
      get;`);
  return loginPromise.then(async result => {
    const { data } = result;
    if (isEmpty(data)) {
      throw new LoginError();
    }
    const element = head(data);
    const dbPassword = element.password.value;
    const match = await bcrypt.compare(password, dbPassword);
    if (!match) {
      throw new LoginError();
    }
    return loadByID(element.token.id);
  });
};

export const findAll = args => {
  const { first, after, orderBy = 'email' } = args;
  return paginate('match $m isa User', { first, after, orderBy });
};

export const findById = userId => loadByID(userId);

export const userDelete = id => deleteByID(id);

export const userDeleteRelation = relationId => deleteByID(relationId);

export const userAddRelation = (userId, input) =>
  createRelation(userId, input).then(userObject =>
    notify(BUS_TOPICS.User.EDIT_TOPIC, userObject)
  );

export const userCleanContext = (user, userId) => {
  delEditContext(user, userId);
  return findById(userId).then(userObject =>
    notify(BUS_TOPICS.User.EDIT_TOPIC, userObject)
  );
};

export const userEditContext = (user, userId, input) => {
  setEditContext(user, userId, input);
  findById(userId).then(userObject =>
    notify(BUS_TOPICS.User.EDIT_TOPIC, userObject)
  );
};

export const userEditField = (userId, input) =>
  editInputTx(userId, input).then(user =>
    notify(BUS_TOPICS.User.EDIT_TOPIC, user)
  );

export const deleteUserByEmail = email => {
  const delUser = qk(`match $x has email "${email}"; delete $x;`);
  return delUser.then(result => {
    if (isEmpty(result.data)) {
      throw new FunctionalError({ message: "User doesn't exist" });
    } else {
      return email;
    }
  });
};

// Token related
export const findByTokenId = tokenId => {
  const userByToken = qk(
    `match $token isa Token has uuid "${tokenId}" has revoked false; 
                 $token has duration $duration; 
                 $token has created $created; 
                 (authorization:$token, client:$client); 
                 get;`
  );
  return userByToken.then(result => {
    const { data } = result;
    if (isEmpty(data)) return undefined;
    // Token duration validation
    const element = head(data);
    const creation = moment(element.created.value);
    const maxDuration = moment.duration(element.duration.value);
    const currentDuration = moment.duration(moment().diff(creation));
    if (currentDuration > maxDuration) return undefined;
    return loadByID(element.client.id);
  });
};
