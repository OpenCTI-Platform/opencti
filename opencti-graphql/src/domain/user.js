import { head, isEmpty, join, map } from 'ramda';
import uuid from 'uuid/v4';
import moment from 'moment';
import bcrypt from 'bcryptjs';
import { sign } from 'jsonwebtoken';
import { delUserContext } from '../database/redis';
import { AuthenticationFailure } from '../config/errors';
import conf, {
  BUS_TOPICS,
  OPENCTI_DEFAULT_DURATION,
  OPENCTI_ISSUER,
  OPENCTI_TOKEN,
  OPENCTI_WEB_TOKEN
} from '../config/conf';
import {
  getObject,
  deleteEntityById,
  getById,
  notify,
  now,
  paginate,
  takeWriteTx,
  updateAttribute,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  prepareString,
  queryOne
} from '../database/grakn';

// Security related
export const generateOpenCTIWebToken = () => ({
  uuid: uuid(),
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
  const signedToken = sign(token, conf.get('app:secret'));
  res.cookie('opencti_token', signedToken, {
    httpOnly: true,
    expires,
    secure: conf.get('app:cookie_secure')
  });
};

export const findAll = args => {
  const { first, after, orderBy = 'email', isUser } = args;
  return paginate(`match $m isa User${isUser ? '; $m has email $e' : ''}`, {
    first,
    after,
    orderBy
  });
};

export const findById = userId => getById(userId);

export const groups = (userId, args) =>
  paginate(
    `match $group isa Group; 
    $rel(grouping:$group, member:$user) isa membership; 
    $user id ${userId}`,
    args
  );

export const token = userId =>
  getObject(
    `match $x isa Token; $rel(authorization:$x, client:$client) isa authorize; $client id ${userId}; offset 0; limit 1; get $x,$rel;`,
    'x',
    'rel'
  ).then(result => sign(result.node, conf.get('app:secret')));

export const addPerson = async (user, newUser) => {
  const wTx = await takeWriteTx();
  const userIterator = await wTx.query(`insert $user isa User 
    has type "user";
    $user has stix_id "${
      user.stix_id ? prepareString(user.stix_id) : `user--${uuid()}`
    }";
    $user has stix_label "";
    $user has alias "";
    $user has name "${prepareString(newUser.name)}";
    $user has description "${prepareString(newUser.description)}";
    $user has created ${newUser.created ? prepareDate(newUser.created) : now()};
    $user has modified ${
      newUser.modified ? prepareDate(newUser.modified) : now()
    };
    $user has revoked false;
    $user has created_at ${now()};
    $user has created_at_day "${dayFormat(now())}";
    $user has created_at_month "${monthFormat(now())}";
    $user has created_at_year "${yearFormat(now())}";   
    $user has updated_at ${now()};
  `);
  const createUser = await userIterator.next();
  const createdUserId = await createUser.map().get('user').id;

  if (user.createdByRef) {
    await wTx.query(`match $from id ${createdUserId};
         $to id ${user.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  await wTx.commit();

  return getById(createdUserId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const addUser = async (user, newUser) => {
  const newToken = generateOpenCTIWebToken();
  const wTx = await takeWriteTx();
  const userIterator = await wTx.query(`insert $user isa User 
    has type "user";
    $user has stix_id "${
      user.stix_id ? prepareString(user.stix_id) : `user--${uuid()}`
    }";
    $user has stix_label "";
    $user has alias "";
    $user has name "${prepareString(newUser.name)}";
    $user has description "${prepareString(newUser.description)}";
    $user has email "${newUser.email}"; ${
    newUser.password
      ? `$user has password "${bcrypt.hashSync(newUser.password)}";`
      : ''
  }
    $user has firstname "${prepareString(newUser.firstname)}";
    $user has lastname "${prepareString(newUser.lastname)}";
    ${
      newUser.language
        ? `$user has language "${prepareString(newUser.language)}";`
        : '$user has language "auto";'
    }
        $user has created ${
          newUser.created ? prepareDate(newUser.created) : now()
        };
    $user has modified ${
      newUser.modified ? prepareDate(newUser.modified) : now()
    };
    $user has revoked false;
    $user has created_at ${now()};
    $user has created_at_day "${dayFormat(now())}";
    $user has created_at_month "${monthFormat(now())}";
    $user has created_at_year "${yearFormat(now())}";      
    $user has updated_at ${now()};
    ${
      newUser.grant
        ? join(' ', map(role => `$user has grant "${role}";`, newUser.grant))
        : ''
    }
  `);

  const createUser = await userIterator.next();
  const createdUserId = await createUser.map().get('user').id;

  if (user.createdByRef) {
    await wTx.query(`match $from id ${createdUserId};
         $to id ${user.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  const tokenIterator = await wTx.query(`insert $token isa Token 
    has type "token"; 
    $token has uuid "${newToken.uuid}";
    $token has name "${newToken.name}";
    $token has created ${newToken.created};
    $token has issuer "${newToken.issuer}";
    $token has revoked ${newToken.revoked};
    $token has duration "${newToken.duration}";
    $token has created_at ${now()};
    $token has updated_at ${now()};
  `);

  const createdToken = await tokenIterator.next();
  await createdToken.map().get('token').id;
  await wTx.query(`match $user isa User has email "${newUser.email}"; 
                   $token isa Token has uuid "${newToken.uuid}"; 
                   insert (client: $user, authorization: $token) isa authorize;`);

  await wTx.commit();

  return getById(createdUserId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

// User related
export const loginFromProvider = async (email, name) => {
  const result = await queryOne(
    `match $client isa User has email "${email}"; (authorization:$token, client:$client); get;`,
    ['client', 'token']
  );
  if (isEmpty(result)) {
    const newUser = {
      name,
      email,
      created: now(),
      password: null
    };
    return addUser({}, newUser).then(() => loginFromProvider(email, name));
  }
  return Promise.resolve(result.token);
};

export const login = async (email, password) => {
  const result = await queryOne(
    `match $client isa User has email "${email}"; (authorization:$token, client:$client); get;`,
    ['client', 'token']
  );
  if (isEmpty(result)) {
    throw new AuthenticationFailure();
  }
  const dbPassword = result.client.password;
  const match = bcrypt.compareSync(password, dbPassword);
  if (!match) {
    throw new AuthenticationFailure();
  }
  return Promise.resolve(result.token);
};

export const logout = async (user, res) => {
  res.clearCookie(OPENCTI_TOKEN);
  await delUserContext(user);
  return user.id;
};

export const userRenewToken = async (user, userId) => {
  const wTx = await takeWriteTx();
  await wTx.query(
    `match $user id ${userId}; $rel(authorization:$token, client:$user); delete $rel, $token;`
  );
  const newToken = generateOpenCTIWebToken();
  const tokenIterator = await wTx.query(`insert $token isa Token 
    has type "token"; 
    $token has uuid "${newToken.uuid}";
    $token has name "${newToken.name}";
    $token has created ${newToken.created};
    $token has issuer "${newToken.issuer}";
    $token has revoked ${newToken.revoked};
    $token has duration "${newToken.duration}";
    $token has created_at ${now()};
    $token has updated_at ${now()};
  `);
  const createdToken = await tokenIterator.next();
  await createdToken.map().get('token').id;
  await wTx.query(
    `match $user id ${userId}"; $token isa Token has uuid "${
      newToken.uuid
    }"; insert (client: $user, authorization: $token) isa authorize;`
  );
  await wTx.commit();
  return getById(userId);
};

export const userDelete = userId => deleteEntityById(userId);

export const userEditField = (user, userId, input) => {
  const { key } = input;
  const value =
    key === 'password' ? [bcrypt.hashSync(head(input.value), 10)] : input.value;
  const finalInput = { key, value };
  return updateAttribute(userId, finalInput).then(userToEdit =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, userToEdit, user)
  );
};

// Token related
export const findByTokenId = async tokenId => {
  const result = await queryOne(
    `match $token isa Token has uuid "${tokenId}" has revoked false; (authorization:$token, client:$client); get;`,
    ['client', 'token']
  );
  if (isEmpty(result)) {
    return undefined;
  }
  const { created } = result.token;
  const maxDuration = moment.duration(result.token.duration);
  const currentDuration = moment.duration(moment().diff(created));
  if (currentDuration > maxDuration) return undefined;
  return result.client;
};
