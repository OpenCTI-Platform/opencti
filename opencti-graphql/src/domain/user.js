import { contains, head, isEmpty, join, map } from 'ramda';
import uuidv5 from 'uuid/v5';
import moment from 'moment';
import bcrypt from 'bcryptjs';
import { sign } from 'jsonwebtoken';
import { delEditContext, setEditContext } from '../database/redis';
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
  multipleAttributes,
  createRelation,
  deleteByID,
  deleteRelation,
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

export const addUser = async (user, newUser) => {
  // const userPassword = await hashPassword(user.password);
  const token = generateOpenCTIWebToken(newUser.email);
  const createUser = qk(`insert $user isa User 
    has type "user";
    $user has name "${newUser.name}";
    $user has email "${newUser.email}";
    $user has firstname "${newUser.firstname}";
    $user has lastname "${newUser.lastname}";
    ${
      newUser.language
        ? `$user has language "${newUser.language}";`
        : '$user has language "auto";'
    }
    $user has created_at ${now()};
    $user has updated_at ${now()};
    ${join(' ', map(role => `$user has grant "${role}";`, newUser.grant))}
  `);
  const createToken = qk(`insert $token isa Token 
    has type "token"; 
    $token has uuid "${token.uuid}";
    $token has name "${token.name}";
    $token has created ${token.created};
    $token has issuer "${token.issuer}";
    $token has revoked ${token.revoked};
    $token has duration "${token.duration}";
    $token has created_at ${now()};
    $token has updated_at ${now()};
  `);
  // Execute user and token creation in parrallel, then create the relation.
  const createPromise = Promise.all([createUser, createToken]);
  return createPromise.then(([resultUser]) =>
    // Create the relation
    qk(`match $user isa User has email "${newUser.email}"; 
                   $token isa Token has uuid "${token.uuid}"; 
                   insert (client: $user, authorization: $token) isa authorize;`).then(
      () => {
        const { data } = resultUser;
        return loadByID(head(data).user.id).then(created =>
          notify(BUS_TOPICS.User.ADDED_TOPIC, created, user)
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
        grant: [ROLE_USER],
        created: now(),
        password: null
      };
      // Create the user then restart the login
      return addUser({}, newUser).then(() =>
        loginFromProvider(email, name)
      );
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
      throw new LoginError();
    }
    const element = head(data);
    const dbPassword = element.password.value;
    const match = bcrypt.compareSync(password, dbPassword);
    if (!match) {
      throw new LoginError();
    }
    return loadByID(element.token.id);
  });
};

export const userDelete = userId => deleteByID(userId);

export const userAddRelation = (user, userId, input) =>
  createRelation(userId, input).then(relationData => {
    notify(BUS_TOPICS.User.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const userDeleteRelation = (user, userId, relationId) =>
  deleteRelation(userId, relationId).then(relationData => {
    notify(BUS_TOPICS.User.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const userCleanContext = (user, userId) => {
  delEditContext(user, userId);
  return loadByID(userId).then(userToEdit =>
    notify(BUS_TOPICS.User.EDIT_TOPIC, userToEdit, user)
  );
};

export const userEditContext = (user, userId, input) => {
  setEditContext(user, userId, input);
  return loadByID(userId).then(userToEdit =>
    notify(BUS_TOPICS.User.EDIT_TOPIC, userToEdit, user)
  );
};

export const userEditField = (user, userId, input) => {
  const { key } = input;
  const value =
    key === 'password' ? bcrypt.hashSync(head(input.value), 10) : input.value;
  let finalInput = { key, value: [value] };
  if (contains(key, multipleAttributes)) {
    finalInput = { key, value };
  }
  return editInputTx(userId, finalInput).then(userToEdit =>
    notify(BUS_TOPICS.User.EDIT_TOPIC, userToEdit, user)
  );
};

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
