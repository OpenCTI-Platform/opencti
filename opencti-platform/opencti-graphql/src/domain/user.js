import * as R from 'ramda';
import { map } from 'ramda';
import moment from 'moment';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import { delEditContext, delUserContext, notify, setEditContext } from '../database/redis';
import { AuthenticationFailure, ForbiddenAccess, FunctionalError } from '../config/errors';
import {
  BUS_TOPICS,
  logApp,
  logAudit,
  OPENCTI_DEFAULT_DURATION,
  OPENCTI_ISSUER,
  OPENCTI_SESSION,
  OPENCTI_WEB_TOKEN,
} from '../config/conf';
import {
  batchListThroughGetTo,
  createEntity,
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  listEntities,
  listThroughGetFrom,
  listThroughGetTo,
  loadById,
  loadThroughGetTo,
  patchAttribute,
  updateAttribute,
} from '../database/middleware';
import {
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_TOKEN,
  ENTITY_TYPE_USER,
} from '../schema/internalObject';
import {
  isInternalRelationship,
  RELATION_ACCESSES_TO,
  RELATION_AUTHORIZED_BY,
  RELATION_HAS_CAPABILITY,
  RELATION_HAS_ROLE,
  RELATION_MEMBER_OF,
} from '../schema/internalRelationship';
import { ABSTRACT_INTERNAL_RELATIONSHIP, BYPASS, OPENCTI_ADMIN_UUID, OPENCTI_SYSTEM_UUID } from '../schema/general';
import { findAll as allMarkings } from './markingDefinition';
import { findAll as findGroups } from './group';
import { generateStandardId } from '../schema/identifier';
import { elLoadBy } from '../database/elasticSearch';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { now } from '../utils/format';
import { applicationSession } from '../database/session';
import {
  convertRelationToAction,
  LOGIN_ACTION,
  LOGOUT_ACTION,
  ROLE_DELETION,
  USER_CREATION,
  USER_DELETION,
} from '../config/audit';
import { buildPagination } from '../database/utils';

const BEARER = 'Bearer ';
const BASIC = 'Basic ';
export const STREAMAPI = 'STREAMAPI';
export const TAXIIAPI = 'TAXIIAPI';
export const ROLE_DEFAULT = 'Default';
export const ROLE_ADMINISTRATOR = 'Administrator';
export const SYSTEM_USER = {
  id: OPENCTI_SYSTEM_UUID,
  name: 'SYSTEM',
  user_email: 'SYSTEM',
  origin: {},
  roles: [{ name: ROLE_ADMINISTRATOR }],
  capabilities: [{ name: BYPASS }],
  allowed_marking: [],
};

export const userWithOrigin = (req, user) => {
  // /!\ This metadata information is used in different ways
  // - In audit logs to identified the user
  // - In stream message to also identifier the user
  // - In logging system to know the level of the error message
  const origin = {
    ip: req.ip,
    user_id: user.id,
    referer: req.headers.referer,
    applicant_id: req.headers['opencti-applicant-id'],
    call_retry_number: req.headers['opencti-retry-number'],
  };
  return { ...user, origin };
};

const extractTokenFromBearer = (authorization) => {
  const isBearer = authorization && authorization.startsWith(BEARER);
  return isBearer ? authorization.substring(BEARER.length) : null;
};

const extractTokenFromBasicAuth = async (authorization) => {
  const isBasic = authorization && authorization.startsWith(BASIC);
  if (isBasic) {
    const b64auth = authorization.substring(BASIC.length);
    const [username, password] = Buffer.from(b64auth, 'base64').toString().split(':');
    // eslint-disable-next-line no-use-before-define
    const { token } = await login(username, password);
    return token?.uuid;
  }
  return null;
};

export const generateOpenCTIWebToken = (tokenValue = uuid()) => ({
  uuid: tokenValue,
  name: OPENCTI_WEB_TOKEN,
  created_at: now(),
  issuer: OPENCTI_ISSUER,
  revoked: false,
  duration: OPENCTI_DEFAULT_DURATION, // 99 years per default
});

export const findById = async (user, userId) => {
  const data = await loadById(user, userId, ENTITY_TYPE_USER);
  return data ? R.dissoc('password', data) : data;
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_USER], args);
};

export const batchGroups = async (user, userIds) => {
  return batchListThroughGetTo(user, userIds, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP);
};

export const token = async (user, userId) => {
  const capabilities = R.map((n) => n.name, user.capabilities);
  if (userId !== user.id && !R.includes('SETACCESSES', capabilities) && !R.includes(BYPASS, capabilities)) {
    throw ForbiddenAccess();
  }
  const userToken = await loadThroughGetTo(SYSTEM_USER, userId, RELATION_AUTHORIZED_BY, ENTITY_TYPE_TOKEN);
  return userToken && userToken.uuid;
};

const internalGetToken = async (userId) => {
  return loadThroughGetTo(SYSTEM_USER, userId, RELATION_AUTHORIZED_BY, ENTITY_TYPE_TOKEN);
};

export const batchRoles = async (user, userId) => {
  return batchListThroughGetTo(user, userId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, { paginate: false });
};

export const getUserAndGlobalMarkings = async (userId, capabilities) => {
  const userGroups = await listThroughGetTo(SYSTEM_USER, userId, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP);
  const groupIds = userGroups.map((r) => r.id);
  const userCapabilities = map((c) => c.name, capabilities);
  const shouldBypass = userCapabilities.includes(BYPASS) || userId === OPENCTI_ADMIN_UUID;
  const allMarkingsPromise = allMarkings(SYSTEM_USER).then((data) => R.map((i) => i.node, data.edges));
  let userMarkingsPromise;
  if (shouldBypass) {
    userMarkingsPromise = allMarkingsPromise;
  } else {
    userMarkingsPromise = listThroughGetTo(SYSTEM_USER, groupIds, RELATION_ACCESSES_TO, ENTITY_TYPE_MARKING_DEFINITION);
  }
  const [userMarkings, markings] = await Promise.all([userMarkingsPromise, allMarkingsPromise]);
  const computedMarkings = [];
  for (let index = 0; index < userMarkings.length; index += 1) {
    const userMarking = userMarkings[index];
    computedMarkings.push(userMarking);
    // Find all marking of same type with rank <=
    const { id, x_opencti_order: order, definition_type: type } = userMarking;
    const matchingMarkings = R.filter((m) => {
      return id !== m.id && m.definition_type === type && m.x_opencti_order <= order;
    }, markings);
    computedMarkings.push(...matchingMarkings);
  }
  return { user: R.uniqBy((m) => m.id, computedMarkings), all: markings };
};

export const getMarkings = async (userId, capabilities) => {
  const marking = await getUserAndGlobalMarkings(userId, capabilities);
  return marking.user;
};

export const getCapabilities = async (userId) => {
  const roles = await listThroughGetTo(SYSTEM_USER, userId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE);
  const roleIds = roles.map((r) => r.id);
  const capabilities = await listThroughGetTo(SYSTEM_USER, roleIds, RELATION_HAS_CAPABILITY, ENTITY_TYPE_CAPABILITY);
  if (userId === OPENCTI_ADMIN_UUID && !R.find(R.propEq('name', BYPASS))(capabilities)) {
    const id = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: BYPASS });
    capabilities.push({ id, standard_id: id, internal_id: id, name: BYPASS });
  }
  return capabilities;
};

export const batchRoleCapabilities = async (user, roleId) => {
  return batchListThroughGetTo(user, roleId, RELATION_HAS_CAPABILITY, ENTITY_TYPE_CAPABILITY, { paginate: false });
};

export const findRoleById = (user, roleId) => {
  return loadById(user, roleId, ENTITY_TYPE_ROLE);
};

export const findRoles = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_ROLE], args);
};

// region session management
export const findSessions = () => {
  const { store } = applicationSession();
  return new Promise((accept) => {
    store.all((err, result) => {
      const sessionsPerUser = R.groupBy(
        (s) => s.user.id,
        R.filter((n) => n.user, result)
      );
      const sessions = Object.entries(sessionsPerUser).map(([k, v]) => {
        return {
          user_id: k,
          sessions: v.map((s) => ({ id: s.id, created: s.user.session_creation })),
        };
      });
      accept(sessions);
    });
  });
};

export const findUserSessions = async (userId) => {
  const sessions = await findSessions();
  const userSessions = sessions.filter((s) => s.user_id === userId);
  if (userSessions.length > 0) {
    return R.head(userSessions).sessions;
  }
  return [];
};

export const fetchSessionTtl = (session) => {
  const { store } = applicationSession();
  return new Promise((accept) => {
    store.expiration(session.id, (err, ttl) => {
      accept(ttl);
    });
  });
};

export const killSession = (id) => {
  const { store } = applicationSession();
  return new Promise((accept) => {
    store.destroy(id, () => {
      accept(id);
    });
  });
};

export const killUserSessions = async (userId) => {
  const sessions = await findUserSessions(userId);
  const sessionsIds = sessions.map((s) => s.id);
  for (let index = 0; index < sessionsIds.length; index += 1) {
    const sessionId = sessionsIds[index];
    await killSession(sessionId);
  }
  return sessionsIds;
};
// endregion

export const findCapabilities = (user, args) => {
  const finalArgs = R.assoc('orderBy', 'attribute_order', args);
  return listEntities(user, [ENTITY_TYPE_CAPABILITY], finalArgs);
};

export const roleDelete = async (user, roleId) => {
  const del = await deleteElementById(user, roleId, ENTITY_TYPE_ROLE);
  logAudit.info(user, ROLE_DELETION, { id: roleId });
  return del;
};

export const roleCleanContext = async (user, roleId) => {
  await delEditContext(user, roleId);
  return loadById(user, roleId, ENTITY_TYPE_ROLE).then((role) =>
    notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user)
  );
};

export const roleEditContext = async (user, roleId, input) => {
  await setEditContext(user, roleId, input);
  return loadById(user, roleId, ENTITY_TYPE_ROLE).then((role) =>
    notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user)
  );
};

const assignRoleToUser = async (user, userId, roleName) => {
  const generateToId = generateStandardId(ENTITY_TYPE_ROLE, { name: roleName });
  const assignInput = {
    fromId: userId,
    toId: generateToId,
    relationship_type: RELATION_HAS_ROLE,
  };
  return createRelation(user, assignInput);
};

export const addUser = async (user, newUser, newToken = generateOpenCTIWebToken()) => {
  const userEmail = newUser.user_email.toLowerCase();
  const existingUser = await elLoadBy(SYSTEM_USER, 'user_email', userEmail, ENTITY_TYPE_USER);
  if (existingUser) {
    throw FunctionalError('User already exists', { email: userEmail });
  }
  // Create the user
  const userToCreate = R.pipe(
    R.assoc('user_email', userEmail),
    R.assoc('password', bcrypt.hashSync(newUser.password ? newUser.password.toString() : uuid())),
    R.assoc('language', newUser.language ? newUser.language : 'auto'),
    R.assoc('external', newUser.external ? newUser.external : false),
    R.dissoc('roles')
  )(newUser);
  const userCreated = await createEntity(user, userToCreate, ENTITY_TYPE_USER);
  // Create token and link it to the user
  const defaultToken = await createEntity(user, newToken, ENTITY_TYPE_TOKEN);
  const input = {
    fromId: userCreated.id,
    toId: defaultToken.id,
    relationship_type: RELATION_AUTHORIZED_BY,
  };
  await createRelation(user, input);
  // Link to the roles
  let userRoles = newUser.roles || []; // Expected roles name
  const defaultRoles = await findRoles(user, { filters: [{ key: 'default_assignation', values: [true] }] });
  if (defaultRoles && defaultRoles.edges.length > 0) {
    userRoles = R.pipe(
      R.map((n) => n.node.name),
      R.append(userRoles),
      R.flatten
    )(defaultRoles.edges);
  }
  await Promise.all(R.map((role) => assignRoleToUser(user, userCreated.id, role), userRoles));
  // Assign default groups to user
  const defaultGroups = await findGroups(user, { filters: [{ key: 'default_assignation', values: [true] }] });
  const relationGroups = defaultGroups.edges.map((e) => ({
    fromId: userCreated.id,
    toId: e.node.internal_id,
    relationship_type: RELATION_MEMBER_OF,
  }));
  await Promise.all(relationGroups.map((relation) => createRelation(user, relation)));
  // Audit log
  const groups = defaultGroups.edges.map((g) => ({ id: g.node.id, name: g.node.name }));
  logAudit.info(user, USER_CREATION, { user: userEmail, roles: userRoles, groups });
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].ADDED_TOPIC, userCreated, user);
};

export const roleEditField = async (user, roleId, input) => {
  const role = await updateAttribute(user, roleId, ENTITY_TYPE_ROLE, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user);
};

// TO DELETE ?
export const roleAddRelation = async (user, roleId, input) => {
  const role = await loadById(user, roleId, ENTITY_TYPE_ROLE);
  if (!role) {
    throw FunctionalError(`Cannot add the relation, ${ENTITY_TYPE_ROLE} cannot be found.`);
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = R.assoc('fromId', roleId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
// TO DELETE ?
export const roleDeleteRelation = async (user, roleId, toId, relationshipType) => {
  const role = await loadById(user, roleId, ENTITY_TYPE_ROLE);
  if (!role) {
    throw FunctionalError('Cannot delete the relation, Role cannot be found.');
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(user, roleId, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user);
};

// User related
export const userEditField = async (user, userId, input) => {
  const { key } = input;
  const value = key === 'password' ? [bcrypt.hashSync(R.head(input.value).toString(), 10)] : input.value;
  const patch = { [key]: value };
  const userToEdit = await patchAttribute(user, userId, ENTITY_TYPE_USER, patch);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userToEdit, user);
};

export const bookmarks = async (user, types) => {
  const currentUser = await loadById(user, user.id, ENTITY_TYPE_USER);
  const bookmarkList =
    types && types.length > 0
      ? R.filter((n) => R.includes(n.type, types), currentUser.bookmarks || [])
      : currentUser.bookmarks || [];
  const filteredBookmarks = await Promise.all(R.map((n) => loadById(user, n.id, n.type), bookmarkList));
  return buildPagination(
    0,
    null,
    filteredBookmarks.map((n) => ({ node: n })),
    filteredBookmarks.length
  );
};

export const addBookmark = async (user, id, type) => {
  const currentUser = await loadById(user, user.id, ENTITY_TYPE_USER);
  const currentBookmarks = currentUser.bookmarks ? currentUser.bookmarks : [];
  const newBookmarks = R.append(
    { id, type },
    R.filter((n) => n.id !== id, currentBookmarks)
  );
  await patchAttribute(user, user.id, ENTITY_TYPE_USER, { bookmarks: newBookmarks });
  return loadById(user, id, type);
};

export const deleteBookmark = async (user, id) => {
  const currentUser = await loadById(user, user.id, ENTITY_TYPE_USER);
  const currentBookmarks = currentUser.bookmarks ? currentUser.bookmarks : [];
  const newBookmarks = R.filter((n) => n.id !== id, currentBookmarks);
  await patchAttribute(user, user.id, ENTITY_TYPE_USER, { bookmarks: newBookmarks });
  return id;
};

export const meEditField = (user, userId, input) => {
  return userEditField(user, userId, input);
};

export const userDelete = async (user, userId) => {
  const userToken = await internalGetToken(userId);
  if (userToken) {
    await deleteElementById(user, userToken.id, ENTITY_TYPE_TOKEN);
  }
  await deleteElementById(user, userId, ENTITY_TYPE_USER);
  logAudit.info(user, USER_DELETION, { user: userId });
  return userId;
};

export const userAddRelation = async (user, userId, input) => {
  const userData = await loadById(user, userId, ENTITY_TYPE_USER);
  if (!userData) {
    throw FunctionalError(`Cannot add the relation, ${ENTITY_TYPE_USER} cannot be found.`);
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = R.assoc('fromId', userId, input);
  const relationData = await createRelation(user, finalInput);
  const operation = convertRelationToAction(input.relationship_type);
  logAudit.info(user, operation, { from: userId, to: input.toId, type: input.relationship_type });
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, relationData, user);
};

export const userDeleteRelation = async (user, userId, toId, relationshipType) => {
  const userData = await loadById(user, userId, ENTITY_TYPE_USER);
  if (!userData) {
    throw FunctionalError('Cannot delete the relation, User cannot be found.');
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(user, userId, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  const operation = convertRelationToAction(relationshipType, false);
  logAudit.info(user, operation, { from: userId, to: toId, type: relationshipType });
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userData, user);
};

export const loginFromProvider = async (email, name, providerRoles = []) => {
  if (!email) {
    throw Error('User email not provided');
  }
  const user = await elLoadBy(SYSTEM_USER, 'user_email', email, ENTITY_TYPE_USER);
  if (!user) {
    const newUser = { name, user_email: email.toLowerCase(), external: true };
    return addUser(SYSTEM_USER, newUser).then(() => loginFromProvider(email, name));
  }
  // Update the basic information
  const userToken = await loadThroughGetTo(SYSTEM_USER, user.id, RELATION_AUTHORIZED_BY, ENTITY_TYPE_TOKEN);
  const inputName = { key: 'name', value: [name] };
  await userEditField(SYSTEM_USER, user.id, inputName);
  const inputExternal = { key: 'external', value: [true] };
  await userEditField(SYSTEM_USER, user.id, inputExternal);
  // Update the roles
  // If roles are specified here, that overwrite the default assignation
  if (providerRoles.length > 0) {
    // 01 - Delete all roles from the user
    const opts = { paginate: false };
    const userRoles = await listThroughGetTo(SYSTEM_USER, user.id, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, opts);
    for (let index = 0; index < userRoles.length; index += 1) {
      const userRole = userRoles[index];
      await userDeleteRelation(SYSTEM_USER, user.id, userRole.id, RELATION_HAS_ROLE);
    }
    // 02 - Create roles from providers
    const rolesCreation = R.map((role) => assignRoleToUser(SYSTEM_USER, user.id, role), providerRoles);
    await Promise.all(rolesCreation);
  }
  return { token: userToken, user };
};

export const login = async (email, password) => {
  const user = await elLoadBy(SYSTEM_USER, 'user_email', email, ENTITY_TYPE_USER);
  if (!user) throw AuthenticationFailure();
  const userToken = await loadThroughGetTo(SYSTEM_USER, user.id, RELATION_AUTHORIZED_BY, ENTITY_TYPE_TOKEN);
  if (!userToken) throw AuthenticationFailure();
  const dbPassword = user.password;
  const match = bcrypt.compareSync(password, dbPassword);
  if (!match) throw AuthenticationFailure();
  // await clearUsersSession(userToken.uuid);
  return { token: userToken, user };
};

export const logout = async (user, req, res) => {
  await delUserContext(user);
  res.clearCookie(OPENCTI_SESSION);
  req.session.destroy();
  logAudit.info(user, LOGOUT_ACTION);
  return user.id;
};

// Token related
const internalGetTokenByUUID = async (tokenUUID) => {
  return elLoadBy(SYSTEM_USER, 'uuid', tokenUUID, ENTITY_TYPE_TOKEN);
};

export const userRenewToken = async (user, userId, newToken = generateOpenCTIWebToken()) => {
  // 01. Get current token
  const currentToken = await internalGetToken(userId);
  // 02. Remove the token
  if (currentToken) {
    await deleteElementById(user, currentToken.id, ENTITY_TYPE_TOKEN);
  } else {
    logApp.error(`[INIT] ${userId} user have no token to renew, please report this problem in github`);
    const detachedToken = await internalGetTokenByUUID(newToken.uuid);
    if (detachedToken) {
      await deleteElementById(user, detachedToken.id, ENTITY_TYPE_TOKEN);
    }
  }
  // 03. Create a new one
  const defaultToken = await createEntity(user, newToken, ENTITY_TYPE_TOKEN);
  // 04. Associate new token to user.
  const input = {
    fromId: userId,
    toId: defaultToken.id,
    relationship_type: RELATION_AUTHORIZED_BY,
  };
  await createRelation(user, input);
  return loadById(user, userId, ENTITY_TYPE_USER);
};

const buildSessionUser = (user, tokenUUID = null) => {
  return {
    id: user.id,
    token_uuid: tokenUUID,
    session_creation: now(),
    internal_id: user.internal_id,
    user_email: user.user_email,
    capabilities: user.capabilities.map((c) => ({ id: c.id, internal_id: c.internal_id, name: c.name })),
    allowed_marking: user.allowed_marking.map((m) => ({
      id: m.id,
      internal_id: m.internal_id,
      definition_type: m.definition_type,
    })),
    all_marking: user.all_marking.map((m) => ({
      id: m.id,
      internal_id: m.internal_id,
      definition_type: m.definition_type,
    })),
  };
};
const resolveUserByToken = async (tokenValue) => {
  const userToken = await elLoadBy(SYSTEM_USER, 'uuid', tokenValue, ENTITY_TYPE_TOKEN);
  // Check token
  if (!userToken || userToken.revoked === true) return undefined;
  const { created_at: createdAt, duration } = userToken;
  const maxDuration = moment.duration(duration);
  const currentDuration = moment.duration(moment().diff(createdAt));
  if (currentDuration > maxDuration) return undefined;
  // Build user
  const users = await listThroughGetFrom(SYSTEM_USER, userToken.id, RELATION_AUTHORIZED_BY, ENTITY_TYPE_USER);
  if (users.length === 0 || users.length > 1) return undefined;
  const client = R.head(users);
  const capabilities = await getCapabilities(client.id);
  const marking = await getUserAndGlobalMarkings(client.id, capabilities);
  const user = { ...client, capabilities, allowed_marking: marking.user, all_marking: marking.all };
  return buildSessionUser(user, tokenValue);
};
export const resolveUserById = async (id) => {
  const client = await loadById(SYSTEM_USER, id, ENTITY_TYPE_USER);
  const capabilities = await getCapabilities(client.id);
  const marking = await getUserAndGlobalMarkings(client.id, capabilities);
  const user = { ...client, capabilities, allowed_marking: marking.user, all_marking: marking.all };
  return buildSessionUser(user);
};

// Authentication process

export const authenticateUser = async (req, opts = {}) => {
  const { providerToken = null, provider = null } = opts;
  const auth = req?.session?.user;
  let loginProvider = provider;
  if (auth) {
    // User already identified
    return auth;
  }
  // If user not identified, try to extract token from request
  let tokenUUID = providerToken;
  // If no specified token, try first the bearer
  if (!tokenUUID) {
    tokenUUID = extractTokenFromBearer(req?.headers.authorization);
    loginProvider = 'Bearer';
  }
  // If no bearer specified, try with basic auth
  if (!tokenUUID) {
    tokenUUID = await extractTokenFromBasicAuth(req?.headers.authorization);
    loginProvider = 'BasicAuth';
  }
  // Get user from the token if found
  if (tokenUUID) {
    try {
      const user = await resolveUserByToken(tokenUUID);
      if (req && user) {
        // Build the user session with only required fields
        logAudit.info(userWithOrigin(req, user), LOGIN_ACTION, { provider: loginProvider });
        req.session.user = user;
      }
      return user;
    } catch (err) {
      logApp.error(`[OPENCTI] Authentication error ${tokenUUID}`, { error: err });
    }
  }
  return undefined;
};

export const initAdmin = async (email, password, tokenValue) => {
  const admin = await findById(SYSTEM_USER, OPENCTI_ADMIN_UUID);
  const tokenAdmin = generateOpenCTIWebToken(tokenValue);
  if (admin) {
    // Update admin fields
    const patch = { user_email: email, password: bcrypt.hashSync(password, 10), external: true };
    await patchAttribute(SYSTEM_USER, admin.id, ENTITY_TYPE_USER, patch);
    // Renew the token
    await userRenewToken(SYSTEM_USER, admin.id, tokenAdmin);
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
  return loadById(user, userId, ENTITY_TYPE_USER).then((userToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userToReturn, user)
  );
};

export const userEditContext = async (user, userId, input) => {
  await setEditContext(user, userId, input);
  return loadById(user, userId, ENTITY_TYPE_USER).then((userToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userToReturn, user)
  );
};
// endregion
