import { assoc, find as rFind, head, isNil, pipe, map, dissoc, append, flatten, propEq, includes } from 'ramda';
import moment from 'moment';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import {
  clearAccessCache,
  delEditContext,
  delUserContext,
  getAccessCache,
  notify,
  setEditContext,
  storeAccessCache,
} from '../database/redis';
import { AuthenticationFailure, ForbiddenAccess, FunctionalError } from '../config/errors';
import conf, {
  BUS_TOPICS,
  logger,
  OPENCTI_DEFAULT_DURATION,
  OPENCTI_ISSUER,
  OPENCTI_TOKEN,
  OPENCTI_WEB_TOKEN,
} from '../config/conf';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  deleteRelationsByFromAndTo,
  escapeString,
  executeWrite,
  find,
  findWithConnectedRelations,
  listEntities,
  load,
  loadEntityById,
  now,
  updateAttribute,
} from '../database/grakn';
import { buildPagination } from '../database/utils';
import {
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_TOKEN,
  ENTITY_TYPE_USER,
  OPENCTI_ADMIN_UUID,
  RELATION_AUTHORIZED_BY,
  RELATION_HAS_CAPABILITY,
  RELATION_HAS_ROLE,
  RELATION_MEMBER_OF,
  generateStandardId,
} from '../utils/idGenerator';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';

// region utils
export const BYPASS = 'BYPASS';

export const generateOpenCTIWebToken = (tokenValue = uuid()) => ({
  uuid: tokenValue,
  name: OPENCTI_WEB_TOKEN,
  created_at: now(),
  issuer: OPENCTI_ISSUER,
  revoked: false,
  duration: OPENCTI_DEFAULT_DURATION, // 99 years per default
});

export const setAuthenticationCookie = (token, res) => {
  const creation = moment(token.created_at);
  const maxDuration = moment.duration(token.duration);
  const expires = creation.add(maxDuration).toDate();
  if (res) {
    res.cookie('opencti_token', token.uuid, {
      httpOnly: true,
      expires,
      secure: conf.get('app:cookie_secure'),
    });
  }
};
// endregion

export const SYSTEM_USER = { name: 'system' };
export const ROLE_DEFAULT = 'Default';
export const ROLE_ADMINISTRATOR = 'Administrator';

export const findById = async (userId) => {
  const data = await loadEntityById(userId, ENTITY_TYPE_USER);
  return data ? dissoc('password', data) : data;
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_USER], ['name', 'aliases'], args);
};

export const groups = (userId) => {
  return findWithConnectedRelations(
    `match $to isa Group, has internal_id $to_id; 
    $rel(${RELATION_MEMBER_OF}_from:$from, ${RELATION_MEMBER_OF}_to:$to) isa ${RELATION_MEMBER_OF}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $from isa User, has internal_id "${escapeString(userId)}";
    get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const token = async (userId, args, context) => {
  const capabilities = map((n) => n.name, context.user.capabilities);
  if (userId !== context.user.id && !includes('SETACCESSES', capabilities) && !includes('BYPASS', capabilities)) {
    throw ForbiddenAccess();
  }
  const element = await load(
    `match $to isa Token;
    $rel(${RELATION_AUTHORIZED_BY}_from:$from, ${RELATION_AUTHORIZED_BY}_to:$to) isa ${RELATION_AUTHORIZED_BY};
    $from has internal_id "${escapeString(userId)}"; get;`,
    ['to']
  );
  return element && element.to;
};

const internalGetToken = async (userId) => {
  const query = `match $to isa Token;
  $rel(${RELATION_AUTHORIZED_BY}_from:$from, ${RELATION_AUTHORIZED_BY}_to:$to) isa ${RELATION_AUTHORIZED_BY};
  $from has internal_id "${escapeString(userId)}"; get;`;
  const element = await load(query, ['to']);
  return element && element.to;
};

const internalGetTokenByUUID = async (tokenUUID) => {
  const query = `match $token isa Token; $token has internal_id $token_id; $token has uuid "${escapeString(
    tokenUUID
  )}"; get;`;
  return load(query, ['token']).then((result) => result && result.token);
};

const clearUserTokenCache = (userId) => {
  return internalGetToken(userId).then((tokenValue) => clearAccessCache(tokenValue.uuid));
};

export const getRoles = async (userId) => {
  const data = await find(
    `match $client isa User, has internal_id "${escapeString(userId)}";
            (${RELATION_HAS_ROLE}_from: $client, ${RELATION_HAS_ROLE}_to: $role) isa ${RELATION_HAS_ROLE};
            $role has internal_id $role_id;
            get;`,
    ['role']
  );
  return map((r) => r.role, data);
};

export const getCapabilities = async (userId) => {
  const data = await find(
    `match $client isa User, has internal_id "${escapeString(userId)}";
            (${RELATION_HAS_ROLE}_from: $client, ${RELATION_HAS_ROLE}_to: $role) isa ${RELATION_HAS_ROLE}; 
            (${RELATION_HAS_CAPABILITY}_from: $role, ${RELATION_HAS_CAPABILITY}_to: $capability) isa ${RELATION_HAS_CAPABILITY}; 
            $capability has internal_id $capability_id;
            get;`,
    ['capability']
  );
  const capabilities = map((r) => r.capability, data);
  if (userId === OPENCTI_ADMIN_UUID && !rFind(propEq('name', BYPASS))(capabilities)) {
    const id = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: BYPASS });
    capabilities.push({ id, internal_id: id, name: BYPASS });
  }
  return capabilities;
};

export const getRoleCapabilities = async (roleId) => {
  const data = await find(
    `match $role isa Role, has internal_id "${escapeString(roleId)}";
            (${RELATION_HAS_CAPABILITY}_from: $role, ${RELATION_HAS_CAPABILITY}_to: $capability) isa ${RELATION_HAS_CAPABILITY}; 
            $role has internal_id $role_id;
            $capability has internal_id $capability_id;
            get;`,
    ['capability']
  );
  return map((r) => r.capability, data);
};

export const findRoleById = (roleId) => {
  return loadEntityById(roleId, ENTITY_TYPE_ROLE);
};

export const findRoles = (args) => {
  return listEntities([ENTITY_TYPE_ROLE], ['name'], args);
};

export const findCapabilities = (args) => {
  const finalArgs = assoc('orderBy', 'attribute_order', args);
  return listEntities([ENTITY_TYPE_CAPABILITY], ['description'], finalArgs);
};

export const removeRole = async (userId, roleName) => {
  await executeWrite(async (wTx) => {
    const query = `match $rel(${RELATION_HAS_ROLE}_from: $from, ${RELATION_HAS_ROLE}_to: $to) isa ${RELATION_HAS_ROLE}; 
            $from has internal_id "${escapeString(userId)}"; 
            $to has name "${escapeString(roleName)}"; 
            delete $rel;`;
    await wTx.query(query, { infer: false });
  });
  await clearUserTokenCache(userId);
  return findById(userId);
};

export const roleRemoveCapability = async (user, roleId, capabilityName) => {
  await executeWrite(async (wTx) => {
    const query = `match $rel(${RELATION_HAS_CAPABILITY}_from: $from, ${RELATION_HAS_CAPABILITY}_to: $to) isa ${RELATION_HAS_CAPABILITY}; 
            $from isa Role, has internal_id "${escapeString(roleId)}"; 
            $to isa Capability, has name $name; { $name contains "${escapeString(capabilityName)}";};
            delete $rel;`;
    await wTx.query(query, { infer: false });
  });
  // Clear cache of every user with this modified role
  const impactedUsers = await findAll({
    filters: [{ key: `${REL_INDEX_PREFIX}${RELATION_HAS_ROLE}.internal_id`, values: [roleId] }],
  });
  await Promise.all(map((e) => clearUserTokenCache(e.node.id), impactedUsers.edges));
  return loadEntityById(roleId, ENTITY_TYPE_ROLE);
};

export const roleDelete = async (user, roleId) => {
  // Clear cache of every user with this deleted role
  const impactedUsers = await findAll({
    filters: [{ key: `${REL_INDEX_PREFIX}${RELATION_HAS_ROLE}.internal_id`, values: [roleId] }],
  });
  await Promise.all(map((e) => clearUserTokenCache(e.node.id), impactedUsers.edges));
  return deleteEntityById(user, roleId, ENTITY_TYPE_ROLE, { noLog: true });
};

export const roleCleanContext = async (user, roleId) => {
  await delEditContext(user, roleId);
  return loadEntityById(roleId, ENTITY_TYPE_ROLE).then((role) =>
    notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user)
  );
};

export const roleEditContext = async (user, roleId, input) => {
  await setEditContext(user, roleId, input);
  return loadEntityById(roleId, ENTITY_TYPE_ROLE).then((role) =>
    notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user)
  );
};
// endregion

export const assignRoleToUser = (user, userId, roleName) => {
  const assignInput = {
    fromId: userId,
    toId: generateStandardId(ENTITY_TYPE_ROLE, { name: roleName }),
    relationship_type: RELATION_HAS_ROLE,
  };
  return createRelation(user, assignInput, { noLog: true });
};

export const addUser = async (user, newUser, newToken = generateOpenCTIWebToken()) => {
  let userRoles = newUser.roles || []; // Expected roles name
  // Assign default roles to user
  const defaultRoles = await findRoles({ filters: [{ key: 'default_assignation', values: [true] }] });
  if (defaultRoles && defaultRoles.edges.length > 0) {
    userRoles = pipe(
      map((n) => n.node.name),
      append(userRoles),
      flatten
    )(defaultRoles.edges);
  }
  const userToCreate = pipe(
    assoc('password', bcrypt.hashSync(newUser.password ? newUser.password.toString() : uuid())),
    assoc('language', newUser.language ? newUser.language : 'auto'),
    assoc('external', newUser.external ? newUser.external : false),
    dissoc('roles')
  )(newUser);
  const userOptions = { noLog: true };
  const userCreated = await createEntity(user, userToCreate, ENTITY_TYPE_USER, userOptions);
  // Create token and link it to the user
  const tokenOptions = { noLog: true };
  const defaultToken = await createEntity(user, newToken, ENTITY_TYPE_TOKEN, tokenOptions);
  const input = {
    fromId: userCreated.id,
    toId: defaultToken.id,
    relationship_type: 'authorized-by',
  };
  await createRelation(user, input, { noLog: true });
  // Link to the roles
  await Promise.all(map((role) => assignRoleToUser(user, userCreated.id, role), userRoles));
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].ADDED_TOPIC, userCreated, user);
};

export const roleEditField = (user, roleId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, roleId, ENTITY_TYPE_ROLE, input, wTx, { noLog: true });
  }).then(async () => {
    const role = await loadEntityById(roleId, ENTITY_TYPE_ROLE);
    return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user);
  });
};

export const roleAddRelation = async (user, roleId, input) => {
  const finalInput = pipe(assoc('fromId', roleId), assoc('relationship_type', RELATION_HAS_CAPABILITY))(input);
  const data = await createRelation(user, finalInput, { noLog: true });
  // Clear cache of every user with this modified role
  const impactedUsers = await findAll({
    filters: [{ key: `${REL_INDEX_PREFIX}${RELATION_HAS_ROLE}.internal_id`, values: [roleId] }],
  });
  await Promise.all(map((e) => clearUserTokenCache(e.node.id), impactedUsers.edges));
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, data, user);
};

// User related
export const userEditField = (user, userId, input) => {
  const { key } = input;
  const value = key === 'password' ? [bcrypt.hashSync(head(input.value).toString(), 10)] : input.value;
  const finalInput = { key, value };
  return executeWrite((wTx) => {
    return updateAttribute(user, userId, ENTITY_TYPE_USER, finalInput, wTx, { noLog: true });
  }).then(async () => {
    const userToEdit = await loadEntityById(userId, ENTITY_TYPE_USER);
    return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userToEdit, user);
  });
};

export const meEditField = (user, userId, input) => {
  return userEditField(user, userId, input);
};

export const userDelete = async (user, userId) => {
  const userToken = await internalGetToken(userId);
  if (userToken) {
    await deleteEntityById(user, userToken.id, ENTITY_TYPE_TOKEN, { noLog: true });
    await clearAccessCache(userToken.uuid);
  }
  await deleteEntityById(user, userId, ENTITY_TYPE_USER);
  return userId;
};

export const userAddRelation = async (user, userId, input) => {
  const finalInput = pipe(assoc('fromId', userId), assoc('fromType', ENTITY_TYPE_USER))(input);
  const data = await createRelation(user, finalInput);
  await clearUserTokenCache(userId);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, data, user);
};

export const userDeleteRelation = async (
  user,
  userId,
  relationId = null,
  toId = null,
  relationship_type = 'relation'
) => {
  if (relationId) {
    await deleteRelationById(user, relationId, 'relation');
  } else if (toId) {
    await deleteRelationsByFromAndTo(user, userId, toId, relationship_type, 'relation');
  } else {
    throw FunctionalError('Cannot delete the relation, missing relationId or toId');
  }
  await clearUserTokenCache(userId);
  const data = await loadEntityById(userId, 'Stix-Domain-Object');
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, data, user);
};

export const loginFromProvider = async (email, name) => {
  const result = await load(
    `match $client isa User, has user_email "${escapeString(email)}"; 
    (${RELATION_AUTHORIZED_BY}_from:$client, ${RELATION_AUTHORIZED_BY}_to:$token); get;`,
    ['client', 'token']
  );
  if (isNil(result)) {
    const newUser = { name, user_email: email, external: true };
    return addUser(SYSTEM_USER, newUser).then(() => loginFromProvider(email, name));
  }
  // update the name
  const inputName = { key: 'name', value: [name] };
  await userEditField(SYSTEM_USER, result.client.id, inputName);
  const inputExternal = { key: 'external', value: [true] };
  await userEditField(SYSTEM_USER, result.client.id, inputExternal);
  await clearAccessCache(result.token.id);
  return result.token;
};

export const login = async (email, password) => {
  const query = `match $client isa User, has user_email "${escapeString(email)}";
   $client has internal_id $client_id;
   (${RELATION_AUTHORIZED_BY}_from:$client, ${RELATION_AUTHORIZED_BY}_to:$token) isa ${RELATION_AUTHORIZED_BY}; 
   $token has internal_id $token_id;
   get;`;
  const result = await load(query, ['client', 'token']);
  if (isNil(result)) throw AuthenticationFailure();
  const dbPassword = result.client.password;
  const match = bcrypt.compareSync(password, dbPassword);
  if (!match) throw AuthenticationFailure();
  await clearAccessCache(result.token.uuid);
  return result.token;
};

export const logout = async (user, res) => {
  res.clearCookie(OPENCTI_TOKEN);
  await clearAccessCache(user.token.uuid);
  await delUserContext(user);
  return user.id;
};

// Token related
export const userRenewToken = async (user, userId, newToken = generateOpenCTIWebToken()) => {
  // 01. Get current token
  const currentToken = await internalGetToken(userId);
  // 02. Remove the token
  if (currentToken) {
    await deleteEntityById(user, currentToken.id, ENTITY_TYPE_TOKEN, { noLog: true });
  } else {
    logger.error(`[GRAKN] ${userId} user have no token to renew, please report this problem in github`);
    const detachedToken = await internalGetTokenByUUID(newToken.uuid);
    if (detachedToken) {
      await deleteEntityById(user, detachedToken.id, ENTITY_TYPE_TOKEN, { noLog: true });
    }
  }
  // 03. Create a new one
  const defaultToken = await createEntity(user, newToken, ENTITY_TYPE_TOKEN, { noLog: true });
  // 04. Associate new token to user.
  const input = {
    fromId: userId,
    toId: defaultToken.id,
    relationship_type: RELATION_AUTHORIZED_BY,
  };
  await createRelation(user, input, { noLog: true });
  return loadEntityById(userId, ENTITY_TYPE_USER);
};

export const findByTokenUUID = async (tokenValue) => {
  // This method is call every time a user to a platform action
  let user = await getAccessCache(tokenValue);
  if (!user) {
    const data = await load(
      `match $token isa Token;
            $token has uuid "${escapeString(tokenValue)}", has revoked false;
            (${RELATION_AUTHORIZED_BY}_from:$client, ${RELATION_AUTHORIZED_BY}_to:$token) isa ${RELATION_AUTHORIZED_BY}; get;`,
      ['token', 'client']
    );
    if (!data) return undefined;
    // eslint-disable-next-line no-shadow
    const { client, token } = data;
    if (!client) return undefined;
    logger.debug(`Setting cache access for ${tokenValue}`);
    const capabilities = await getCapabilities(client.id);
    user = pipe(assoc('token', token), assoc('capabilities', capabilities))(client);
    await storeAccessCache(tokenValue, user);
  }
  const { created_at: createdAt } = user.token;
  const maxDuration = moment.duration(user.token.duration);
  const currentDuration = moment.duration(moment().diff(createdAt));
  if (currentDuration > maxDuration) return undefined;
  return user;
};

// Authentication process
export const authentication = async (tokenUUID) => {
  if (!tokenUUID) return undefined;
  try {
    return await findByTokenUUID(tokenUUID);
  } catch (err) {
    logger.error(`[OPENCTI] Authentication error ${tokenUUID}`, { error: err });
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
  const admin = await findById(OPENCTI_ADMIN_UUID);
  const tokenAdmin = generateOpenCTIWebToken(tokenValue);
  if (admin) {
    // Update admin fields
    await executeWrite(async (wTx) => {
      const inputEmail = { key: 'user_email', value: [email] };
      await updateAttribute(admin, admin.id, ENTITY_TYPE_USER, inputEmail, wTx);
      const inputPassword = { key: 'password', value: [bcrypt.hashSync(password, 10)] };
      await updateAttribute(admin, admin.id, ENTITY_TYPE_USER, inputPassword, wTx, { noLog: true });
      const inputExternal = { key: 'external', value: [true] };
      await updateAttribute(admin, admin.id, ENTITY_TYPE_USER, inputExternal, wTx, { noLog: true });
    });
    // Renew the token
    await userRenewToken(admin, admin.id, tokenAdmin);
  } else {
    const userToCreate = {
      internal_id: OPENCTI_ADMIN_UUID,
      external: true,
      user_email: email.toLowerCase(),
      name: 'admin',
      firstname: 'Admin',
      lastname: 'OpenCTI',
      description: 'Principal admin account',
      password,
    };
    await addUser(SYSTEM_USER, userToCreate, tokenAdmin);
  }
};

// region context
export const userCleanContext = async (user, userId) => {
  await delEditContext(user, userId);
  return loadEntityById(userId, ENTITY_TYPE_USER).then((userToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userToReturn, user)
  );
};

export const userEditContext = async (user, userId, input) => {
  await setEditContext(user, userId, input);
  return loadEntityById(userId, ENTITY_TYPE_USER).then((userToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userToReturn, user)
  );
};
// endregion
