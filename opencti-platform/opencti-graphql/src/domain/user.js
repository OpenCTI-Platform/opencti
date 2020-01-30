import { assoc, head, isNil, pathOr, pipe, map, dissoc } from 'ramda';
import uuid from 'uuid/v4';
import moment from 'moment';
import bcrypt from 'bcryptjs';
import uuidv5 from 'uuid/v5';
import { delUserContext, getAccessCache, notify, storeAccessCache } from '../database/redis';
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
  createEntity,
  createRelation,
  deleteEntityById,
  escapeString,
  executeWrite,
  find,
  listEntities,
  load,
  loadEntityById,
  loadEntityByStixId,
  loadWithConnectedRelations,
  now,
  TYPE_OPENCTI_INTERNAL,
  TYPE_STIX_DOMAIN_ENTITY,
  updateAttribute
} from '../database/grakn';
import { stixDomainEntityDelete } from './stixDomainEntity';

// region utils
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
// endregion

export const OPENCTI_ADMIN_UUID = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';
export const SYSTEM_USER = { name: 'system' };
export const ROLE_DEFAULT = 'Default';
export const ROLE_ADMINISTRATOR = 'Administrator';

export const findById = async (userId, args) => {
  let user;
  if (userId.match(/[a-z-]+--[\w-]{36}/g)) {
    user = await loadEntityByStixId(userId);
  } else {
    user = await loadEntityById(userId, args);
  }
  // Complete with roles and capabilities
  const data = await find(
    `match $client isa User, has internal_id_key "${escapeString(user.id)}";
            (client: $client, position: $role) isa user_role; 
            (position: $role, capability: $capability) isa role_capability; 
            get;`,
    ['client', 'role', 'capability']
  );
  const roles = map(r => r.role, data);
  const capabilities = map(r => r.capability, data);
  return pipe(
    // Assign
    assoc('roles', roles),
    assoc('capabilities', capabilities)
  )(user);
};
export const findAll = args => {
  return listEntities(['User'], ['email', 'firstname', 'lastname'], args);
};
export const token = (userId, args, context) => {
  if (userId !== context.user.id) {
    throw new ForbiddenAccess();
  }
  return loadWithConnectedRelations(
    `match $x isa Token;
    $rel(authorization:$x, client:$client) isa authorize;
    $client has internal_id_key "${escapeString(userId)}"; get; offset 0; limit 1;`,
    'x',
    'rel'
  ).then(result => result.node.uuid);
};
export const getTokenId = async userId => {
  return loadWithConnectedRelations(
    `match $x isa Token;
    $rel(authorization:$x, client:$client) isa authorize;
    $client has internal_id_key "${escapeString(userId)}"; get; offset 0; limit 1;`,
    'x',
    'rel'
  ).then(result => pathOr(null, ['node', 'id'], result));
};

export const addPerson = async (user, newUser) => {
  const created = await createEntity(newUser, 'User', { modelType: TYPE_STIX_DOMAIN_ENTITY, stixIdType: 'identity' });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
export const addUser = async (user, newUser, newToken = generateOpenCTIWebToken()) => {
  const userRoles = newUser.roles || [];
  if (!userRoles.includes(ROLE_DEFAULT)) userRoles.push(ROLE_DEFAULT);
  const userToCreate = pipe(
    assoc('password', bcrypt.hashSync(newUser.password ? newUser.password.toString() : uuid())),
    assoc('language', newUser.language ? newUser.language : 'auto'),
    assoc('external', newUser.external ? newUser.external : false),
    dissoc('roles')
  )(newUser);
  const userCreated = await createEntity(userToCreate, 'User', {
    modelType: TYPE_STIX_DOMAIN_ENTITY,
    stixIdType: 'identity'
  });
  // Create token and link it to the user
  const defaultToken = await createEntity(newToken, 'Token', { modelType: TYPE_OPENCTI_INTERNAL, indexable: false });
  const input = { fromRole: 'client', toId: defaultToken.id, toRole: 'authorization', through: 'authorize' };
  await createRelation(userCreated.id, input, { indexable: false });
  // Link to the roles
  const linkRoleCreate = role =>
    createRelation(userCreated.id, {
      fromRole: 'client',
      toId: uuidv5(role, uuidv5.DNS),
      toRole: 'position',
      through: 'user_role'
    });
  await Promise.all(map(role => linkRoleCreate(role), userRoles));
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, userCreated, user);
};

// User related
export const userEditField = (user, userId, input) => {
  const { key } = input;
  const value = key === 'password' ? [bcrypt.hashSync(head(input.value).toString(), 10)] : input.value;
  const finalInput = { key, value };
  return executeWrite(wTx => {
    return updateAttribute(userId, finalInput, wTx);
  }).then(async () => {
    const userToEdit = await loadEntityById(userId);
    return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, userToEdit, user);
  });
};
export const meEditField = (user, userId, input) => {
  const { key } = input;
  if (key === 'grant') {
    throw new ForbiddenAccess();
  }
  return userEditField(user, userId, input);
};
export const userDelete = async userId => {
  const tokenId = await getTokenId(userId);
  if (tokenId) {
    await deleteEntityById(tokenId);
  }
  return stixDomainEntityDelete(userId);
};

export const loginFromProvider = async (email, name) => {
  const result = await load(
    `match $client isa User, has email "${escapeString(email)}"; (authorization:$token, client:$client); get;`,
    ['client', 'token']
  );
  if (isNil(result)) {
    const newUser = { name, email, external: true, grant: conf.get('app:default_roles') };
    return addUser(SYSTEM_USER, newUser).then(() => loginFromProvider(email, name));
  }
  // update the name
  const inputName = { key: 'name', value: [name] };
  await userEditField(SYSTEM_USER, result.client.id, inputName);
  const inputExternal = { key: 'external', value: [true] };
  await userEditField(SYSTEM_USER, result.client.id, inputExternal);
  return Promise.resolve(result.token);
};
export const login = async (email, password) => {
  const result = await load(
    `match $client isa User, has email "${escapeString(
      email
    )}"; (authorization:$token, client:$client) isa authorize; get;`,
    ['client', 'token']
  );
  if (isNil(result)) throw new AuthenticationFailure();
  const dbPassword = result.client.password;
  const match = bcrypt.compareSync(password, dbPassword);
  if (!match) throw new AuthenticationFailure();
  return result.token;
};
export const logout = async (user, res) => {
  res.clearCookie(OPENCTI_TOKEN);
  await delUserContext(user);
  return user.id;
};

// Token related
export const userRenewToken = async (userId, newToken = generateOpenCTIWebToken()) => {
  // 01. Get current token
  const currentToken = await getTokenId(userId);
  // 02. Remove the token
  if (currentToken) {
    await deleteEntityById(currentToken);
  }
  // 03. Create a new one
  const defaultToken = await createEntity(newToken, 'Token', { modelType: TYPE_OPENCTI_INTERNAL, indexable: false });
  // 04. Associate new token to user.
  const input = { fromRole: 'client', toId: defaultToken.id, toRole: 'authorization', through: 'authorize' };
  await createRelation(userId, input, { indexable: false });
  return loadEntityById(userId);
};
export const findByTokenUUID = async tokenValue => {
  let user = await getAccessCache(tokenValue);
  if (!user) {
    const data = await find(
      `match $token isa Token, has uuid "${escapeString(tokenValue)}", has revoked false;
            (authorization:$token, client:$client) isa authorize;
            (client: $client, position: $role) isa user_role; 
            (position: $role, capability: $capability) isa role_capability; 
            get;`,
      ['client', 'token', 'role', 'capability']
    );
    logger.debug(`Setting cache access for ${tokenValue}`);
    if (isNil(data) || data.length === 0) return undefined;
    const roles = map(r => r.role, data);
    const capabilities = map(r => r.capability, data);
    const first = head(data);
    user = pipe(
      // Assign
      assoc('token', first.token),
      assoc('roles', roles),
      assoc('capabilities', capabilities)
    )(first.client);
    await storeAccessCache(tokenValue, user);
  }
  const { created } = user.token;
  const maxDuration = moment.duration(user.token.duration);
  const currentDuration = moment.duration(moment().diff(created));
  if (currentDuration > maxDuration) return undefined;
  return user;
};

// Authentication process
export const authentication = async tokenUUID => {
  if (!tokenUUID) return undefined;
  try {
    return await findByTokenUUID(tokenUUID);
  } catch (err) {
    logger.error(`[OPENCTI] Authentication error ${tokenUUID} > `, err);
    return undefined;
  }
};

// The static admin account internal ID
/**
 * Create or update the default administrator account.
 * @param email the admin email
 * @param password the admin password
 * @param tokenValue the admin default token
 * @returns {*}
 */
export const initAdmin = async (email, password, tokenValue) => {
  const admin = await findById(OPENCTI_ADMIN_UUID, { noCache: true });
  const tokenAdmin = generateOpenCTIWebToken(tokenValue);
  if (admin) {
    // Update admin fields
    await executeWrite(async wTx => {
      await updateAttribute(admin.id, { key: 'email', value: [email] }, wTx);
      await updateAttribute(admin.id, { key: 'password', value: [bcrypt.hashSync(password, 10)] }, wTx);
      await updateAttribute(admin.id, { key: 'external', value: [true] }, wTx);
    });
    // Renew the token
    await userRenewToken(admin.id, tokenAdmin);
  } else {
    const userToCreate = {
      internal_id_key: OPENCTI_ADMIN_UUID,
      stix_id_key: `identity--${OPENCTI_ADMIN_UUID}`,
      name: 'admin',
      firstname: 'Admin',
      lastname: 'OpenCTI',
      description: 'Principal admin account',
      email,
      password,
      roles: [ROLE_ADMINISTRATOR]
    };
    await addUser(SYSTEM_USER, userToCreate, tokenAdmin);
  }
};
