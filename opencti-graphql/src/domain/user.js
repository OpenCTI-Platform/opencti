import { head, isEmpty, join, map } from 'ramda';
import uuid from 'uuid/v4';
import uuidv5 from 'uuid/v5';
import moment from 'moment';
import bcrypt from 'bcryptjs';
import { sign } from 'jsonwebtoken';
import { delUserContext } from '../database/redis';
import { MissingElement, AuthenticationFailure } from '../config/errors';
import conf, {
  BUS_TOPICS,
  OPENCTI_DEFAULT_DURATION,
  OPENCTI_ISSUER,
  OPENCTI_TOKEN,
  OPENCTI_WEB_TOKEN,
  ROLE_USER
} from '../config/conf';
import {
  qkObjUnique,
  deleteByID,
  loadByID,
  notify,
  now,
  paginate,
  qk,
  editInputTx,
  dayFormat,
  monthFormat,
  yearFormat,
  prepareString
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
  const signedToken = sign(token, conf.get('app:secret'));
  res.cookie('opencti_token', signedToken, {
    httpOnly: true,
    expires,
    secure: conf.get('app:cookie_secure')
  });
};

export const findAll = args => {
  const { first, after, orderBy = 'email' } = args;
  return paginate('match $m isa User', { first, after, orderBy });
};

export const findById = userId => loadByID(userId);

export const groups = (userId, args) =>
  paginate(
    `match $group isa Group; 
    $rel(grouping:$group, member:$user) isa membership; 
    $user id ${userId}`,
    args
  );

export const token = userId =>
  qkObjUnique(
    `match $x isa Token; 
    $rel(authorization:$x, client:$client) isa authorize; 
    $client id ${userId}; offset 0; limit 1; get $x,$rel;`,
    'x',
    'rel'
  ).then(result => sign(result.node, conf.get('app:secret')));

export const addPerson = async (user, newUser) => {
  const createPerson = qk(`insert $user isa User 
    has type "user";
    $user has stix_id "user--${uuid()}";
    $user has stix_label "";
    $user has stix_label_lowercase "";
    $user has alias "";
    $user has alias_lowercase "";
    $user has name "${prepareString(newUser.name)}";
    $user has description "${prepareString(newUser.description)}";
    $user has name_lowercase "${prepareString(newUser.name.toLowerCase())}";
    $user has description_lowercase "${
      newUser.description
        ? prepareString(newUser.description.toLowerCase())
        : ''
    }";
    $user has created_at ${now()};
    $user has created_at_day "${dayFormat(now())}";
    $user has created_at_month "${monthFormat(now())}";
    $user has created_at_year "${yearFormat(now())}";   
    $user has updated_at ${now()};
  `);
  return createPerson.then(result => {
    const { data } = result;
    return loadByID(head(data).user.id).then(created =>
      notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
    );
  });
};

export const addUser = async (user, newUser) => {
  const newToken = generateOpenCTIWebToken(newUser.email);
  const createUser = qk(`insert $user isa User 
    has type "user";
    $user has stix_id "user--${uuid()}";
    $user has stix_label "";
    $user has stix_label_lowercase "";
    $user has alias "";
    $user has alias_lowercase "";
    $user has name "${prepareString(newUser.name)}";
    $user has description "${prepareString(newUser.description)}";
    $user has name_lowercase "${prepareString(newUser.name.toLowerCase())}";
    $user has description_lowercase "${
      newUser.description
        ? prepareString(newUser.description.toLowerCase())
        : ''
    }";
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
  const createToken = qk(`insert $token isa Token 
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
  // Execute user and token creation in parrallel, then create the relation.
  const createPromise = Promise.all([createUser, createToken]);
  return createPromise.then(([resultUser]) =>
    // Create the relation
    qk(`match $user isa User has email "${newUser.email}"; 
                   $token isa Token has uuid "${newToken.uuid}"; 
                   insert (client: $user, authorization: $token) isa authorize;`).then(
      () => {
        const { data } = resultUser;
        return loadByID(head(data).user.id).then(created =>
          notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
        );
      }
    )
  );
};

// User related
export const loginFromProvider = (email, name) => {
  // Try to get the user.
  const loginPromise = qk(`match $client isa User has email "${email}";
      (authorization:$token, client:$client); 
      get;`);
  return loginPromise.then(result => {
    const { data } = result;
    if (isEmpty(data)) {
      // We need to create the user because we trust the provider
      const newUser = {
        name,
        email,
        created: now(),
        password: null
      };
      // Create the user then restart the login
      return addUser({}, newUser).then(() => loginFromProvider(email, name));
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
  return loginPromise.then(result => {
    const { data } = result;
    if (isEmpty(data)) {
      throw new AuthenticationFailure();
    }
    const element = head(data);
    const dbPassword = element.password.value;
    const match = bcrypt.compareSync(password, dbPassword);
    if (!match) {
      throw new AuthenticationFailure();
    }
    return loadByID(element.token.id);
  });
};

export const logout = async (user, res) => {
  res.clearCookie(OPENCTI_TOKEN);
  await delUserContext(user);
  return user.id;
};

export const userDelete = userId => deleteByID(userId);

export const userEditField = (user, userId, input) => {
  const { key } = input;
  const value =
    key === 'password' ? [bcrypt.hashSync(head(input.value), 10)] : input.value;
  const finalInput = { key, value };
  return editInputTx(userId, finalInput).then(userToEdit =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, userToEdit, user)
  );
};

export const deleteUserByEmail = email => {
  const delUser = qk(`match $x has email "${email}"; delete $x;`);
  return delUser.then(result => {
    if (isEmpty(result.data)) {
      throw new MissingElement({ message: "User doesn't exist" });
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
