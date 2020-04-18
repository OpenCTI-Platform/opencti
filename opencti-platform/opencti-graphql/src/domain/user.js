import { assoc, find as rFind, head, isNil, pipe, map, dissoc, append, flatten, propOr, propEq } from 'ramda';
import moment from 'moment';
import bcrypt from 'bcryptjs';
import { v4 as uuid, v5 as uuidv5 } from 'uuid';
import {
  clearAccessCache,
  delEditContext,
  delUserContext,
  getAccessCache,
  notify,
  setEditContext,
  storeAccessCache,
} from '../database/redis';
import { AuthenticationFailure, ForbiddenAccess } from '../config/errors';
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
  loadEntityByStixId,
  loadWithConnectedRelations,
  now,
  updateAttribute,
} from '../database/grakn';
import { buildPagination, TYPE_OPENCTI_INTERNAL, TYPE_STIX_DOMAIN_ENTITY } from '../database/utils';

// region utils
export const BYPASS = 'BYPASS';
export const generateOpenCTIWebToken = (tokenValue = uuid()) => ({
  uuid: tokenValue,
  name: OPENCTI_WEB_TOKEN,
  created: now(),
  issuer: OPENCTI_ISSUER,
  revoked: false,
  duration: OPENCTI_DEFAULT_DURATION, // 99 years per default
});
export const setAuthenticationCookie = (token, res) => {
  const creation = moment(token.created);
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

export const OPENCTI_ADMIN_UUID = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';
export const SYSTEM_USER = { name: 'system' };
export const ROLE_DEFAULT = 'Default';
export const ROLE_ADMINISTRATOR = 'Administrator';

export const findById = async (userId, options = { isUser: false }) => {
  let data;
  if (userId.match(/[a-z-]+--[\w-]{36}/g)) {
    data = await loadEntityByStixId(userId, 'User', options);
  } else {
    data = await loadEntityById(userId, 'User', options);
  }
  if (!options.isUser) {
    data = pipe(dissoc('user_email'), dissoc('password'))(data);
  }
  return data;
};
export const findAll = async (args = {}, isUser = false) => {
  const filters = propOr([], 'filters', args);
  let data = await listEntities(
    ['User'],
    ['user_email', 'firstname', 'lastname'],
    assoc('filters', isUser ? append({ key: 'external', values: ['EXISTS'] }, filters) : filters, args)
  );
  if (!isUser) {
    data = assoc(
      'edges',
      map(
        (n) => ({
          cursor: n.cursor,
          node: pipe(dissoc('user_email'), dissoc('password'))(n.node),
          relation: n.relation,
        }),
        data.edges
      ),
      data
    );
  }
  return data;
};
export const organizations = (userId) => {
  return findWithConnectedRelations(
    `match $to isa Organization; $rel(part_of:$from, gather:$to) isa gathering;
     $from isa User, has internal_id_key "${escapeString(userId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const groups = (userId) => {
  return findWithConnectedRelations(
    `match $to isa Group; $rel(member:$from, grouping:$to) isa membership;
   $from isa User, has internal_id_key "${escapeString(userId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const token = (userId, args, context) => {
  if (context.user.id !== OPENCTI_ADMIN_UUID && userId !== context.user.id) {
    throw new ForbiddenAccess();
  }
  return loadWithConnectedRelations(
    `match $x isa Token;
    $rel(authorization:$x, client:$client) isa authorize;
    $client has internal_id_key "${escapeString(userId)}"; get; offset 0; limit 1;`,
    'x',
    { extraRelKey: 'rel', noCache: true }
  ).then((result) => result.node.uuid);
};

const internalGetToken = async (userId) => {
  return loadWithConnectedRelations(
    `match $x isa Token;
    $rel(authorization:$x, client:$client) isa authorize;
    $client has internal_id_key "${escapeString(userId)}"; get; offset 0; limit 1;`,
    'x',
    { extraRelKey: 'rel', noCache: true }
  ).then((result) => result && result.node);
};

const internalGetTokenByUUID = async (tokenUUID) => {
  return load(`match $token isa Token; $x has uuid "${escapeString(tokenUUID)}"; get;`, ['token'], {
    noCache: true,
  }).then((result) => result && result.token);
};

const clearUserTokenCache = (userId) => {
  return internalGetToken(userId).then((tokenValue) => clearAccessCache(tokenValue.uuid));
};
export const getRoles = async (userId) => {
  const data = await find(
    `match $client isa User, has internal_id_key "${escapeString(userId)}";
            (client: $client, position: $role) isa user_role; 
            get;`,
    ['role']
  );
  return map((r) => r.role, data);
};
export const getCapabilities = async (userId) => {
  const data = await find(
    `match $client isa User, has internal_id_key "${escapeString(userId)}";
            (client: $client, position: $role) isa user_role; 
            (position: $role, capability: $capability) isa role_capability; 
            get;`,
    ['capability']
  );
  const capabilities = map((r) => r.capability, data);
  if (userId === OPENCTI_ADMIN_UUID && !rFind(propEq('name', BYPASS))(capabilities)) {
    const id = uuidv5(BYPASS, uuidv5.DNS);
    capabilities.push({ id, internal_id_key: id, name: BYPASS });
  }
  return capabilities;
};
export const getRoleCapabilities = async (roleId) => {
  const data = await find(
    `match $role isa Role, has internal_id_key "${escapeString(roleId)}";
            (position: $role, capability: $capability) isa role_capability; 
            get;`,
    ['capability']
  );
  return map((r) => r.capability, data);
};

export const findRoleById = (toolId) => {
  if (toolId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(toolId, 'Role');
  }
  return loadEntityById(toolId, 'Role');
};
export const findRoles = (args) => {
  return listEntities(['Role'], ['name'], args);
};
export const findCapabilities = (args) => {
  const finalArgs = assoc('orderBy', 'ordering', args);
  return listEntities(['Capability'], ['description'], finalArgs);
};

export const removeRole = async (userId, roleName) => {
  await executeWrite(async (wTx) => {
    const query = `match $rel(client: $from, position: $to) isa user_role; 
            $from has internal_id_key "${escapeString(userId)}"; 
            $to has name "${escapeString(roleName)}"; 
            delete $rel;`;
    await wTx.tx.query(query, { infer: false });
  });
  await clearUserTokenCache(userId);
  return findById(userId, { isUser: true });
};
export const roleRemoveCapability = async (roleId, capabilityName) => {
  await executeWrite(async (wTx) => {
    const query = `match $rel(position: $from, capability: $to) isa role_capability; 
            $from isa Role, has internal_id_key "${escapeString(roleId)}"; 
            $to isa Capability, has name $name; { $name contains "${escapeString(capabilityName)}";}; 
            delete $rel;`;
    await wTx.tx.query(query, { infer: false });
  });
  // Clear cache of every user with this modified role
  const impactedUsers = await findAll({ filters: [{ key: 'rel_user_role.internal_id_key', values: [roleId] }] });
  await Promise.all(map((e) => clearUserTokenCache(e.node.id), impactedUsers.edges));
  return loadEntityById(roleId, 'Role');
};
export const roleDelete = async (roleId) => {
  // Clear cache of every user with this deleted role
  const impactedUsers = await findAll({ filters: [{ key: 'rel_user_role.internal_id_key', values: [roleId] }] });
  await Promise.all(map((e) => clearUserTokenCache(e.node.id), impactedUsers.edges));
  return deleteEntityById(roleId, 'Role');
};
export const roleCleanContext = (user, roleId) => {
  delEditContext(user, roleId);
  return loadEntityById(roleId, 'Role').then((role) => notify(BUS_TOPICS.Role.EDIT_TOPIC, role, user));
};
export const roleEditContext = (user, roleId, input) => {
  setEditContext(user, roleId, input);
  return loadEntityById(roleId, 'Role').then((role) => notify(BUS_TOPICS.Role.EDIT_TOPIC, role, user));
};
// endregion

export const addPerson = async (user, newUser) => {
  const created = await createEntity(newUser, 'User', {
    modelType: TYPE_STIX_DOMAIN_ENTITY,
    stixIdType: 'identity',
  });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
export const assignRoleToUser = (userId, roleName) => {
  return createRelation(
    userId,
    {
      fromType: 'User',
      fromRole: 'client',
      toId: uuidv5(roleName, uuidv5.DNS),
      toType: 'Role',
      toRole: 'position',
      through: 'user_role',
    },
    { indexable: false }
  );
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
  const userOptions = { modelType: TYPE_STIX_DOMAIN_ENTITY, stixIdType: 'identity' };
  const userCreated = await createEntity(userToCreate, 'User', userOptions);
  // Create token and link it to the user
  const tokenOptions = { modelType: TYPE_OPENCTI_INTERNAL, indexable: false };
  const defaultToken = await createEntity(newToken, 'Token', tokenOptions);
  const input = {
    fromType: 'User',
    fromRole: 'client',
    toId: defaultToken.id,
    toType: 'Token',
    toRole: 'authorization',
    through: 'authorize',
  };
  await createRelation(userCreated.id, input, { indexable: false });
  // Link to the roles
  await Promise.all(map((role) => assignRoleToUser(userCreated.id, role), userRoles));
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, userCreated, user);
};
export const roleEditField = (user, roleId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(roleId, 'Role', input, wTx);
  }).then(async () => {
    const userToEdit = await loadEntityById(roleId, 'Role');
    return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, userToEdit, user);
  });
};
export const roleAddRelation = async (user, roleId, input) => {
  const finalInput = pipe(assoc('through', 'role_capability'), assoc('fromType', 'Role'))(input);
  const data = await createRelation(roleId, finalInput, { indexable: false });
  // Clear cache of every user with this modified role
  const impactedUsers = await findAll({ filters: [{ key: 'rel_user_role.internal_id_key', values: [roleId] }] });
  await Promise.all(map((e) => clearUserTokenCache(e.node.id), impactedUsers.edges));
  return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, data, user);
};
// User related
export const userEditField = (user, userId, input) => {
  const { key } = input;
  const value = key === 'password' ? [bcrypt.hashSync(head(input.value).toString(), 10)] : input.value;
  const finalInput = { key, value };
  return executeWrite((wTx) => {
    return updateAttribute(userId, 'User', finalInput, wTx);
  }).then(async () => {
    const userToEdit = await loadEntityById(userId, 'User');
    return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, userToEdit, user);
  });
};
export const personEditField = async (user, userId, input) => {
  const data = await loadEntityById(userId, 'User');
  if (!isNil(data.external)) {
    throw new ForbiddenAccess();
  }
  return executeWrite((wTx) => {
    return updateAttribute(userId, 'User', input, wTx);
  }).then(async () => {
    const userToEdit = await loadEntityById(userId, 'User');
    return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, userToEdit, user);
  });
};
export const meEditField = (user, userId, input) => {
  return userEditField(user, userId, input);
};
export const userDelete = async (userId) => {
  const userToken = await internalGetToken(userId);
  await deleteEntityById(userToken.id, 'Token', { noCache: true });
  await clearAccessCache(userToken.uuid);
  await deleteEntityById(userId, 'User');
  return userId;
};
export const personDelete = async (personId) => {
  const data = await loadEntityById(personId, 'User');
  if (!isNil(data.external)) throw new ForbiddenAccess();
  await deleteEntityById(personId, 'User');
  return personId;
};
export const userAddRelation = async (user, userId, input) => {
  const finalInput = assoc('fromType', 'User', input);
  const data = await createRelation(userId, finalInput);
  await clearUserTokenCache(userId);
  return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, data, user);
};
export const userDeleteRelation = async (user, userId, relationId = null, toId = null, relationType = 'relation') => {
  if (relationId) {
    await deleteRelationById(relationId, 'relation');
  } else if (toId) {
    await deleteRelationsByFromAndTo(userId, toId, relationType, 'relation');
  } else {
    throw new Error('Cannot delete the relation, missing relationId or toId');
  }
  await clearUserTokenCache(userId);
  const data = await loadEntityById(userId, 'Stix-Domain-Entity');
  return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, data, user);
};
export const personAddRelation = async (user, userId, input) => {
  if (!['tagged', 'created_by_ref', 'object_marking_refs'].includes(input.through)) {
    throw new ForbiddenAccess();
  }
  const finalInput = assoc('fromType', 'User', input);
  const data = await createRelation(userId, finalInput);
  return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, data, user);
};
export const personDeleteRelation = async (
  user,
  userId,
  relationId = null,
  toId = null,
  relationType = 'stix_relation_embedded'
) => {
  if (relationId) {
    await deleteRelationById(relationId, 'stix_relation_embedded');
  } else if (toId) {
    await deleteRelationsByFromAndTo(userId, toId, relationType, 'stix_relation_embedded');
  } else {
    throw new Error('Cannot delete the relation, missing relationId or toId');
  }
  const data = await loadEntityById(userId, 'User');
  return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, data, user);
};
export const stixDomainEntityEditField = async (user, stixDomainEntityId, input) => {
  const stixDomainEntity = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
  if (stixDomainEntity.entity_type === 'user' && !isNil(stixDomainEntity.external)) {
    throw new ForbiddenAccess();
  }
  return executeWrite((wTx) => {
    return updateAttribute(stixDomainEntityId, 'Stix-Domain-Entity', input, wTx);
  }).then(async () => {
    const stixDomain = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
    return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomain, user);
  });
};
export const loginFromProvider = async (email, name) => {
  const result = await load(
    `match $client isa User, has user_email "${escapeString(email)}"; (authorization:$token, client:$client); get;`,
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
  const result = await load(
    `match $client isa User, has user_email "${escapeString(email)}";
     (authorization:$token, client:$client) isa authorize; get;`,
    ['client', 'token'],
    { noCache: true } // Because of the fetching of the token that not in cache
  );
  if (isNil(result)) throw new AuthenticationFailure();
  const dbPassword = result.client.password;
  const match = bcrypt.compareSync(password, dbPassword);
  if (!match) throw new AuthenticationFailure();
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
export const userRenewToken = async (userId, newToken = generateOpenCTIWebToken()) => {
  // 01. Get current token
  const currentToken = await internalGetToken(userId);
  // 02. Remove the token
  if (currentToken) {
    await deleteEntityById(currentToken.id, 'Token', { noCache: true });
  } else {
    logger.error(`[GRAKN] ${userId} user have no token to renew, please report this problem in github`);
    const detachedToken = await internalGetTokenByUUID(newToken.uuid);
    if (detachedToken) {
      await deleteEntityById(detachedToken.id, 'Token', { noCache: true });
    }
  }
  // 03. Create a new one
  const defaultToken = await createEntity(newToken, 'Token', { modelType: TYPE_OPENCTI_INTERNAL, indexable: false });
  // 04. Associate new token to user.
  const input = {
    fromType: 'User',
    fromRole: 'client',
    toId: defaultToken.id,
    toType: 'Token',
    toRole: 'authorization',
    through: 'authorize',
  };
  await createRelation(userId, input, { indexable: false });
  return loadEntityById(userId, 'User');
};
export const findByTokenUUID = async (tokenValue) => {
  // This method is call every time a user to a platform action
  let user = await getAccessCache(tokenValue);
  if (!user) {
    const data = await load(
      `match $token isa Token, has uuid "${escapeString(tokenValue)}", has revoked false;
            (authorization:$token, client:$client) isa authorize; get;`,
      ['token', 'client'],
      { noCache: true }
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
  const { created } = user.token;
  const maxDuration = moment.duration(user.token.duration);
  const currentDuration = moment.duration(moment().diff(created));
  if (currentDuration > maxDuration) return undefined;
  return user;
};

// Authentication process
export const authentication = async (tokenUUID) => {
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
  const admin = await findById(OPENCTI_ADMIN_UUID, { isUser: true, noCache: true });
  const tokenAdmin = generateOpenCTIWebToken(tokenValue);
  if (admin) {
    // Update admin fields
    await executeWrite(async (wTx) => {
      await updateAttribute(admin.id, 'User', { key: 'user_email', value: [email] }, wTx);
      await updateAttribute(admin.id, 'User', { key: 'password', value: [bcrypt.hashSync(password, 10)] }, wTx);
      await updateAttribute(admin.id, 'User', { key: 'external', value: [true] }, wTx);
    });
    // Renew the token
    await userRenewToken(admin.id, tokenAdmin);
  } else {
    const userToCreate = {
      internal_id_key: OPENCTI_ADMIN_UUID,
      stix_id_key: `identity--${OPENCTI_ADMIN_UUID}`,
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
