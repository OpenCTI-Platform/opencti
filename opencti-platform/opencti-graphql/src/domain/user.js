import { head, isNil, join, map } from 'ramda';
import uuid from 'uuid/v4';
import moment from 'moment';
import bcrypt from 'bcryptjs';
import { delUserContext } from '../database/redis';
import { AuthenticationFailure, ForbiddenAccess } from '../config/errors';
import conf, {
  BUS_TOPICS,
  logger,
  OPENCTI_DEFAULT_DURATION,
  OPENCTI_ISSUER,
  OPENCTI_TOKEN,
  OPENCTI_WEB_TOKEN
} from '../config/conf';
import {
  escapeString,
  getObject,
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
  queryOne,
  commitWriteTx
} from '../database/grakn';
import { index } from '../database/elasticSearch';

// Security related
export const generateOpenCTIWebToken = (tokenValue = uuid()) => ({
  uuid: tokenValue,
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
  if (res) {
    res.cookie('opencti_token', token.uuid, {
      httpOnly: true,
      expires,
      secure: conf.get('app:cookie_secure')
    });
  }
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

export const findByEmail = async userEmail => {
  const result = await queryOne(
    `match $user isa User, has email "${escapeString(userEmail)}"; get;`,
    ['user']
  );
  if (result) {
    return result.user;
  }
  return null;
};

export const groups = (userId, args) =>
  paginate(
    `match $group isa Group; 
    $rel(grouping:$group, member:$user) isa membership; 
    $user has internal_id "${escapeString(userId)}"`,
    args
  );

export const token = (userId, args, context) => {
  if (userId !== context.user.id) {
    throw new ForbiddenAccess();
  }
  return getObject(
    `match $x isa Token;
    $rel(authorization:$x, client:$client) isa authorize;
    $client has internal_id "${escapeString(
      userId
    )}"; get $x, $rel; offset 0; limit 1;`,
    'x',
    'rel'
  ).then(result => result.node.uuid);
};

export const addPerson = async (user, newUser) => {
  const wTx = await takeWriteTx();
  const internalId = newUser.internal_id
    ? escapeString(newUser.internal_id)
    : uuid();
  const query = `insert $user isa User,
    has internal_id "${internalId}",
    has entity_type "user",
    has stix_id "${
      newUser.stix_id ? escapeString(newUser.stix_id) : `identity--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(newUser.name)}",
    has description "${escapeString(newUser.description)}",
    has created ${newUser.created ? prepareDate(newUser.created) : now()},
    has modified ${newUser.modified ? prepareDate(newUser.modified) : now()},
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}", 
    has updated_at ${now()};
  `;
  logger.debug(`[GRAKN - infer: false] ${query}`);
  const userIterator = await wTx.tx.query(query);
  const createUser = await userIterator.next();
  const createdUserId = await createUser.map().get('user').id;

  if (user.createdByRef) {
    await wTx.tx.query(`match $from id ${createdUserId};
         $to has internal_id "${escapeString(user.createdByRef)}";
         insert (so: $from, creator: $to)
         isa created_by_ref, has internal_id "${uuid()}";`);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    index('stix-domain-entities', 'stix_domain_entity', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};

export const addUser = async (
  user,
  newUser,
  newToken = generateOpenCTIWebToken()
) => {
  const wTx = await takeWriteTx();
  const internalId = newUser.internal_id
    ? escapeString(newUser.internal_id)
    : uuid();
  const query = `insert $user isa User,
    has internal_id "${internalId}",
    has entity_type "user",
    has stix_id "${
      newUser.stix_id ? escapeString(newUser.stix_id) : `identity--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(newUser.name)}",
    has description "${escapeString(newUser.description)}",
    has email "${escapeString(newUser.email)}",
    ${
      newUser.password
        ? `has password "${bcrypt.hashSync(newUser.password)}",`
        : ''
    }
    has firstname "${escapeString(newUser.firstname)}",
    has lastname "${escapeString(newUser.lastname)}",
    ${
      newUser.language
        ? `has language "${escapeString(newUser.language)}",`
        : 'has language "auto",'
    }
    has created ${newUser.created ? prepareDate(newUser.created) : now()},
    has modified ${newUser.modified ? prepareDate(newUser.modified) : now()},
    ${
      newUser.grant
        ? join(
            ' ',
            map(role => `has grant "${escapeString(role)}",`, newUser.grant)
          )
        : ''
    }
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}" ,    
    has updated_at ${now()};
  `;
  logger.debug(`[GRAKN - infer: false] ${query}`);
  const userIterator = await wTx.tx.query(query);

  const createUser = await userIterator.next();
  const createdUserId = await createUser.map().get('user').id;

  if (user.createdByRef) {
    await wTx.tx.query(`match $from id ${createdUserId};
         $to has internal_id "${escapeString(user.createdByRef)}";
         insert (so: $from, creator: $to)
         isa created_by_ref, has internal_id "${uuid()}";`);
  }

  const tokenIterator = await wTx.tx.query(`insert $token isa Token,
    has internal_id "${uuid()}",
    has entity_type "token",
    has uuid "${newToken.uuid}",
    has name "${newToken.name}",
    has created ${newToken.created},
    has issuer "${newToken.issuer}",
    has revoked ${newToken.revoked},
    has duration "${newToken.duration}",
    has created_at ${now()},
    has updated_at ${now()};
  `);

  const createdToken = await tokenIterator.next();
  await createdToken.map().get('token').id;
  await wTx.tx.query(`match $user isa User, has email "${newUser.email}"; 
                   $token isa Token, has uuid "${newToken.uuid}"; 
                   insert (client: $user, authorization: $token) isa authorize, has internal_id "${uuid()}";`);

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    index('stix-domain-entities', 'stix_domain_entity', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};

// User related
export const loginFromProvider = async (email, name) => {
  const result = await queryOne(
    `match $client isa User, has email "${escapeString(
      email
    )}"; (authorization:$token, client:$client); get;`,
    ['client', 'token']
  );
  if (isNil(result)) {
    const newUser = {
      name,
      email,
      created: now(),
      password: null,
      grant: conf.get('app:default_roles')
    };
    return addUser({}, newUser).then(() => loginFromProvider(email, name));
  }
  return Promise.resolve(result.token);
};

export const login = async (email, password) => {
  const result = await queryOne(
    `match $client isa User, has email "${escapeString(
      email
    )}"; (authorization:$token, client:$client); get;`,
    ['client', 'token']
  );
  if (isNil(result)) {
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

export const userRenewToken = async (
  userId,
  newToken = generateOpenCTIWebToken()
) => {
  const wTx = await takeWriteTx();
  await wTx.tx.query(
    `match $user has internal_id "${escapeString(userId)}";
    $rel(authorization:$token, client:$user);
    delete $rel, $token;`
  );
  const tokenIterator = await wTx.tx.query(`insert $token isa Token,
    has internal_id "${uuid()}",
    has entity_type "token",
    has uuid "${newToken.uuid}",
    has name "${newToken.name}",
    has created ${newToken.created},
    has issuer "${newToken.issuer}",
    has revoked ${newToken.revoked},
    has duration "${newToken.duration}",
    has created_at ${now()},
    has updated_at ${now()};
  `);
  const createdToken = await tokenIterator.next();
  await createdToken.map().get('token').id;
  await wTx.tx.query(
    `match $user has internal_id "${escapeString(userId)}";
    $token isa Token,
    has uuid "${newToken.uuid}";
    insert (client: $user, authorization: $token) isa authorize, has internal_id "${uuid()}";`
  );
  await commitWriteTx(wTx);
  return getById(userId);
};

export const userEditField = (user, userId, input) => {
  const { key } = input;
  const value =
    key === 'password' ? [bcrypt.hashSync(head(input.value), 10)] : input.value;
  const finalInput = { key, value };
  return updateAttribute(userId, finalInput).then(userToEdit => {
    index('stix-domain-entities', 'stix_domain_entity', userToEdit);
    return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, userToEdit, user);
  });
};

export const meEditField = (user, userId, input) => {
  const { key } = input;
  if (key === 'grant') {
    throw new ForbiddenAccess();
  }
  const value =
    key === 'password' ? [bcrypt.hashSync(head(input.value), 10)] : input.value;
  const finalInput = { key, value };
  return updateAttribute(userId, finalInput).then(userToEdit => {
    index('stix-domain-entities', 'stix_domain_entity', userToEdit);
    return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, userToEdit, user);
  });
};

// Token related
export const findByTokenUUID = async tokenValue => {
  const result = await queryOne(
    `match $token isa Token,
    has uuid "${escapeString(tokenValue)}",
    has revoked false;
    (authorization:$token, client:$client); get;`,
    ['client', 'token']
  );
  if (isNil(result)) {
    return undefined;
  }
  const { created } = result.token;
  const maxDuration = moment.duration(result.token.duration);
  const currentDuration = moment.duration(moment().diff(created));
  if (currentDuration > maxDuration) return undefined;
  return result.client;
};

// The static admin account internal ID
const OPENCTI_ADMIN_DNS = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';
/**
 * Create or update the default administrator account.
 * @param email the admin email
 * @param password the admin password
 * @param tokenValue the admin default token
 * @returns {*}
 */
export const initAdmin = async (email, password, tokenValue) => {
  let admin = await findByEmail(email);
  if (admin === null) {
    admin = await findById(OPENCTI_ADMIN_DNS);
  }
  const user = { name: 'system' };
  const tokenAdmin = generateOpenCTIWebToken(tokenValue);
  if (admin) {
    // Update email and password
    await userEditField(user, admin.id, {
      key: 'email',
      value: [email]
    });
    await userEditField(user, admin.id, {
      key: 'password',
      value: [password]
    });
    // Renew the token
    await userRenewToken(admin.id, tokenAdmin);
  } else {
    await addUser(
      user,
      {
        internal_id: OPENCTI_ADMIN_DNS,
        stix_id: `identity--${OPENCTI_ADMIN_DNS}`,
        name: 'admin',
        firstname: 'Admin',
        lastname: 'OpenCTI',
        description: 'Principal admin account',
        email,
        password,
        grant: ['ROLE_ROOT', 'ROLE_ADMIN']
      },
      tokenAdmin
    );
  }
};
