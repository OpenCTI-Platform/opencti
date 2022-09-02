import * as R from 'ramda';
import { map } from 'ramda';
import { authenticator } from 'otplib';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import { delEditContext, delUserContext, notify, setEditContext } from '../database/redis';
import { AuthenticationFailure, ForbiddenAccess, FunctionalError } from '../config/errors';
import { BUS_TOPICS, logApp, logAudit, OPENCTI_SESSION } from '../config/conf';
import {
  batchListThroughGetTo,
  createEntity,
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  listThroughGetTo,
  patchAttribute,
  storeLoadById,
  updateAttribute,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_USER, } from '../schema/internalObject';
import {
  isInternalRelationship,
  RELATION_ACCESSES_TO,
  RELATION_HAS_CAPABILITY,
  RELATION_HAS_ROLE,
  RELATION_MEMBER_OF,
} from '../schema/internalRelationship';
import { ABSTRACT_INTERNAL_RELATIONSHIP, OPENCTI_ADMIN_UUID, OPENCTI_SYSTEM_UUID } from '../schema/general';
import { findAll as allMarkings } from './markingDefinition';
import { findAll as findGroups } from './group';
import { generateStandardId } from '../schema/identifier';
import { elLoadBy } from '../database/engine';
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
import { buildPagination, isEmptyField, isNotEmptyField } from '../database/utils';
import { BYPASS, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';

const BEARER = 'Bearer ';
const BASIC = 'Basic ';
export const STREAMAPI = 'STREAMAPI';
export const TAXIIAPI = 'TAXIIAPI';
export const ROLE_DEFAULT = 'Default';

export const userWithOrigin = (req, user) => {
  // /!\ This metadata information is used in different ways
  // - In audit logs to identified the user
  // - In stream message to also identifier the user
  // - In logging system to know the level of the error message
  const origin = {
    ip: req?.ip,
    user_id: user?.id,
    referer: req?.headers.referer,
    applicant_id: req?.headers['opencti-applicant-id'],
    call_retry_number: req?.headers['opencti-retry-number'],
  };
  return { ...user, origin };
};

const extractTokenFromBearer = (authorization) => {
  const isBearer = authorization && authorization.startsWith(BEARER);
  return isBearer ? authorization.substring(BEARER.length) : null;
};

const extractInfoFromBasicAuth = (authorization) => {
  const isBasic = authorization && authorization.startsWith(BASIC);
  if (isBasic) {
    const b64auth = authorization.substring(BASIC.length);
    const [username, password] = Buffer.from(b64auth, 'base64').toString().split(':');
    return { username, password };
  }
  return {};
};

const extractTokenFromBasicAuth = async (authorization) => {
  const { username, password } = extractInfoFromBasicAuth(authorization);
  if (username && password) {
    // eslint-disable-next-line no-use-before-define
    const { api_token: tokenUUID } = await login(username, password);
    return tokenUUID;
  }
  return null;
};

export const findById = async (user, userId) => {
  const data = await storeLoadById(user, userId, ENTITY_TYPE_USER);
  return data ? R.dissoc('password', data) : data;
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_USER], args);
};

export const batchGroups = async (user, userId, opts = {}) => {
  return batchListThroughGetTo(user, userId, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP, opts);
};

export const batchRoles = async (user, userId) => {
  return batchListThroughGetTo(user, userId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, { paginate: false });
};

export const computeAvailableMarkings = (markings, all) => {
  const computedMarkings = [];
  for (let index = 0; index < markings.length; index += 1) {
    const mark = markings[index];
    // Find all marking of same type with rank <=
    const { id } = mark;
    const findMarking = R.find((m) => m.id === id, all);
    computedMarkings.push(findMarking);
    const { x_opencti_order: order, definition_type: type } = findMarking;
    const matchingMarkings = R.filter((m) => {
      return id !== m.id && m.definition_type === type && m.x_opencti_order <= order;
    }, all);
    computedMarkings.push(...matchingMarkings);
  }
  return R.uniqBy((m) => m.id, computedMarkings);
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
  const computedMarkings = computeAvailableMarkings(userMarkings, markings);
  return { user: computedMarkings, all: markings };
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
  return storeLoadById(user, roleId, ENTITY_TYPE_ROLE);
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
  return storeLoadById(user, roleId, ENTITY_TYPE_ROLE).then((role) => notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user));
};

export const roleEditContext = async (user, roleId, input) => {
  await setEditContext(user, roleId, input);
  return storeLoadById(user, roleId, ENTITY_TYPE_ROLE).then((role) => notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user));
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

const assignGroupToUser = async (user, userId, groupName) => {
  const generateToId = generateStandardId(ENTITY_TYPE_GROUP, { name: groupName });
  const assignInput = {
    fromId: userId,
    toId: generateToId,
    relationship_type: RELATION_MEMBER_OF,
  };
  return createRelation(user, assignInput);
};

export const addUser = async (user, newUser) => {
  const userEmail = newUser.user_email.toLowerCase();
  const existingUser = await elLoadBy(SYSTEM_USER, 'user_email', userEmail, ENTITY_TYPE_USER);
  if (existingUser) {
    throw FunctionalError('User already exists', { email: userEmail });
  }
  // Create the user
  const userToCreate = R.pipe(
    R.assoc('user_email', userEmail),
    R.assoc('api_token', newUser.api_token ? newUser.api_token : uuid()),
    R.assoc('password', bcrypt.hashSync(newUser.password ? newUser.password.toString() : uuid())),
    R.assoc('theme', newUser.theme ? newUser.theme : 'default'),
    R.assoc('language', newUser.language ? newUser.language : 'auto'),
    R.assoc('external', newUser.external ? newUser.external : false),
    R.dissoc('roles')
  )(newUser);
  const userCreated = await createEntity(user, userToCreate, ENTITY_TYPE_USER);
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
  const { element } = await updateAttribute(user, roleId, ENTITY_TYPE_ROLE, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, element, user);
};

export const roleAddRelation = async (user, roleId, input) => {
  const role = await storeLoadById(user, roleId, ENTITY_TYPE_ROLE);
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

export const roleDeleteRelation = async (user, roleId, toId, relationshipType) => {
  const role = await storeLoadById(user, roleId, ENTITY_TYPE_ROLE);
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
export const userEditField = async (user, userId, inputs) => {
  for (let index = 0; index < inputs.length; index += 1) {
    const input = inputs[index];
    if (input.key === 'password') {
      input.value = [bcrypt.hashSync(R.head(input.value).toString())];
    }
  }
  const { element } = await updateAttribute(user, userId, ENTITY_TYPE_USER, inputs);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, element, user);
};

export const deleteBookmark = async (user, id) => {
  const currentUser = await storeLoadById(user, user.id, ENTITY_TYPE_USER);
  const currentBookmarks = currentUser.bookmarks ? currentUser.bookmarks : [];
  const newBookmarks = R.filter((n) => n.id !== id, currentBookmarks);
  await patchAttribute(user, user.id, ENTITY_TYPE_USER, { bookmarks: newBookmarks });
  return id;
};

export const bookmarks = async (user, types) => {
  const currentUser = await storeLoadById(user, user.id, ENTITY_TYPE_USER);
  const bookmarkList = types && types.length > 0
    ? R.filter((n) => R.includes(n.type, types), currentUser.bookmarks || [])
    : currentUser.bookmarks || [];
  const filteredBookmarks = [];
  // eslint-disable-next-line no-restricted-syntax
  for (const bookmark of bookmarkList) {
    const loadedBookmark = await storeLoadById(user, bookmark.id, bookmark.type);
    if (isNotEmptyField(loadedBookmark)) {
      filteredBookmarks.push(loadedBookmark);
    } else {
      await deleteBookmark(user, bookmark.id);
    }
  }
  return buildPagination(
    0,
    null,
    filteredBookmarks.map((n) => ({ node: n })),
    filteredBookmarks.length
  );
};

export const addBookmark = async (user, id, type) => {
  const currentUser = await storeLoadById(user, user.id, ENTITY_TYPE_USER);
  const currentBookmarks = currentUser.bookmarks ? currentUser.bookmarks : [];
  const newBookmarks = R.append(
    { id, type },
    R.filter((n) => n.id !== id, currentBookmarks)
  );
  await patchAttribute(user, user.id, ENTITY_TYPE_USER, { bookmarks: newBookmarks });
  return storeLoadById(user, id, type);
};

export const meEditField = (user, userId, inputs, password = null) => {
  const input = R.head(inputs);
  const { key } = input;
  if (key === 'password') {
    const dbPassword = user.session_password;
    const match = bcrypt.compareSync(password, dbPassword);
    if (!match) throw FunctionalError('The current password you have provided is not valid');
  }
  if (user.external && (key === 'user_email' || key === 'user_name')) {
    throw ForbiddenAccess();
  }
  if (key === 'api_token') {
    throw ForbiddenAccess();
  }
  return userEditField(user, userId, inputs);
};

export const userDelete = async (user, userId) => {
  await deleteElementById(user, userId, ENTITY_TYPE_USER);
  logAudit.info(user, USER_DELETION, { user: userId });
  return userId;
};

export const userAddRelation = async (user, userId, input) => {
  const userData = await storeLoadById(user, userId, ENTITY_TYPE_USER);
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

export const userDeleteRelation = async (user, targetUser, toId, relationshipType) => {
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(user, targetUser.id, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  const operation = convertRelationToAction(relationshipType, false);
  logAudit.info(user, operation, { from: targetUser.id, to: toId, type: relationshipType });
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, targetUser, user);
};

export const userIdDeleteRelation = async (user, userId, toId, relationshipType) => {
  const userData = await storeLoadById(user, userId, ENTITY_TYPE_USER);
  if (!userData) {
    throw FunctionalError('Cannot delete the relation, User cannot be found.');
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  return userDeleteRelation(user, userData, toId, relationshipType);
};

export const loginFromProvider = async (userInfo, providerRoles = [], providerGroups = []) => {
  const { email, name: providedName, firstname, lastname } = userInfo;
  if (isEmptyField(email)) {
    throw Error('User email not provided');
  }
  const name = isEmptyField(providedName) ? email : providedName;
  const user = await elLoadBy(SYSTEM_USER, 'user_email', email, ENTITY_TYPE_USER);
  if (!user) {
    // If user doesnt exists, create it. Providers are trusted
    const newUser = { name, firstname, lastname, user_email: email.toLowerCase(), external: true };
    return addUser(SYSTEM_USER, newUser).then(() => {
      // After user creation, reapply login to manage roles and groups
      return loginFromProvider(userInfo, providerRoles, providerGroups);
    });
  }
  // Update the basic information
  const patch = { name, firstname, lastname, external: true };
  await patchAttribute(SYSTEM_USER, user.id, ENTITY_TYPE_USER, patch);
  // Update the roles
  // If roles are specified here, that overwrite the default assignation
  if (providerRoles.length > 0) {
    // 01 - Delete all roles from the user
    const opts = { paginate: false };
    const userRoles = await listThroughGetTo(SYSTEM_USER, user.id, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, opts);
    for (let index = 0; index < userRoles.length; index += 1) {
      const userRole = userRoles[index];
      await userDeleteRelation(SYSTEM_USER, user, userRole.id, RELATION_HAS_ROLE);
    }
    // 02 - Create roles from providers
    const rolesCreation = R.map((role) => assignRoleToUser(SYSTEM_USER, user.id, role), providerRoles);
    await Promise.all(rolesCreation);
  }
  // Update the groups
  // If groups are specified here, that overwrite the default assignation
  if (providerGroups.length > 0) {
    // 01 - Delete all groups from the user
    const opts = { paginate: false };
    const userGroups = await listThroughGetTo(SYSTEM_USER, user.id, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP, opts);
    for (let index = 0; index < userGroups.length; index += 1) {
      const userGroup = userGroups[index];
      await userDeleteRelation(SYSTEM_USER, user, userGroup.id, RELATION_MEMBER_OF);
    }
    // 02 - Create groups from providers
    const groupsCreation = R.map((group) => assignGroupToUser(SYSTEM_USER, user.id, group), providerGroups);
    await Promise.all(groupsCreation);
  }
  return user;
};

export const login = async (email, password) => {
  const user = await elLoadBy(SYSTEM_USER, 'user_email', email, ENTITY_TYPE_USER);
  if (!user) throw AuthenticationFailure();
  const dbPassword = user.password;
  const match = bcrypt.compareSync(password, dbPassword);
  if (!match) throw AuthenticationFailure();
  return user;
};

export const otpUserGeneration = (user) => {
  const secret = authenticator.generateSecret();
  const uri = authenticator.keyuri(user.user_email, 'OpenCTI', secret);
  return { secret, uri };
};

export const otpUserActivation = async (user, { secret, code }) => {
  const isValidated = authenticator.check(code, secret);
  if (isValidated) {
    const uri = authenticator.keyuri(user.user_email, 'OpenCTI', secret);
    const patch = { otp_activated: true, otp_secret: secret, otp_qr: uri };
    const { element } = await patchAttribute(user, user.id, ENTITY_TYPE_USER, patch);
    return element;
  }
  throw AuthenticationFailure();
};

export const otpUserDeactivation = async (user, id) => {
  const patch = { otp_activated: false, otp_secret: '', otp_qr: '' };
  const { element } = await patchAttribute(user, id, ENTITY_TYPE_USER, patch);
  return element;
};

export const otpUserLogin = (req, user, { code }) => {
  if (!user.otp_activated) {
    throw AuthenticationFailure();
  }
  const isValidated = authenticator.check(code, user.otp_secret);
  if (!isValidated) {
    throw AuthenticationFailure();
  }
  req.session.user.otp_validated = isValidated;
  return isValidated;
};

export const logout = async (user, req, res) => {
  await delUserContext(user);
  return new Promise((resolve, reject) => {
    res.clearCookie(OPENCTI_SESSION);
    req.session.regenerate((err) => {
      if (err) {
        reject(err);
        return;
      }
      logAudit.info(user, LOGOUT_ACTION);
      resolve(user.id);
    });
  });
};

const buildSessionUser = (user, provider) => {
  return {
    id: user.id,
    session_creation: now(),
    session_password: user.password,
    api_token: user.api_token,
    internal_id: user.internal_id,
    user_email: user.user_email,
    otp_activated: user.otp_activated,
    // 2FA is implicitly validated when login from token
    otp_validated: !user.otp_activated || provider === AUTH_BEARER,
    otp_secret: user.otp_secret,
    name: user.name,
    external: user.external,
    login_provider: provider,
    capabilities: user.capabilities.map((c) => ({ id: c.id, internal_id: c.internal_id, name: c.name })),
    allowed_marking: user.allowed_marking.map((m) => ({
      id: m.id,
      standard_id: m.standard_id,
      internal_id: m.internal_id,
      definition_type: m.definition_type,
    })),
    all_marking: user.all_marking.map((m) => ({
      id: m.id,
      standard_id: m.standard_id,
      internal_id: m.internal_id,
      definition_type: m.definition_type,
    })),
  };
};

const buildCompleteUser = async (client) => {
  if (!client) return undefined;
  const capabilities = await getCapabilities(client.id);
  const marking = await getUserAndGlobalMarkings(client.id, capabilities);
  return { ...client, capabilities, allowed_marking: marking.user, all_marking: marking.all };
};

export const resolveUserById = async (id) => {
  if (id === OPENCTI_SYSTEM_UUID) {
    return SYSTEM_USER;
  }
  const client = await storeLoadById(SYSTEM_USER, id, ENTITY_TYPE_USER);
  return buildCompleteUser(client);
};

const resolveUserByToken = async (tokenValue) => {
  const client = await elLoadBy(SYSTEM_USER, 'api_token', tokenValue, ENTITY_TYPE_USER);
  return buildCompleteUser(client);
};

export const userRenewToken = async (user, userId) => {
  const patch = { api_token: uuid() };
  await patchAttribute(user, userId, ENTITY_TYPE_USER, patch);
  return storeLoadById(user, userId, ENTITY_TYPE_USER);
};

export const authenticateUser = async (req, user, provider, token = '') => {
  // Build the user session with only required fields
  const completeUser = await buildCompleteUser(user);
  logAudit.info(userWithOrigin(req, user), LOGIN_ACTION, { provider });
  const sessionUser = buildSessionUser(completeUser, provider);
  req.session.user = sessionUser;
  req.session.session_provider = { provider, token };
  return sessionUser;
};

const AUTH_BEARER = 'Bearer';
const AUTH_BASIC = 'BasicAuth';
export const authenticateUserFromRequest = async (req, res) => {
  const auth = req.session?.user;
  // If user already have a session
  if (auth) {
    // User already identified, we need to enforce the session validity
    const { provider, token } = req.session.session_provider;
    // For bearer, validate that the bearer is the same as the session
    if (provider === AUTH_BEARER) {
      const currentToken = extractTokenFromBearer(req.headers.authorization);
      if (currentToken !== token) {
        // Session doesn't match, kill the current session and try to re auth
        await logout(auth, req, res);
        return authenticateUserFromRequest(req, res);
      }
    }
    // For basic auth, validate that user and password match the session
    if (provider === AUTH_BASIC) {
      const { username, password } = extractInfoFromBasicAuth(req.headers.authorization);
      const sameUsername = username === auth.user_email;
      const sessionPassword = auth.session_password;
      const passwordCompare = isNotEmptyField(password) && isNotEmptyField(sessionPassword);
      const samePassword = passwordCompare && bcrypt.compareSync(password, sessionPassword);
      if (!sameUsername || !samePassword) {
        // Session doesn't match, kill the current session and try to re auth
        await logout(auth, req, res);
        return authenticateUserFromRequest(req, res);
      }
    }
    // Other providers doesn't need specific validation, session management is enough
    // If everything ok, return the authenticated user.
    return auth;
  }
  // If user not identified, try to extract token from bearer
  let loginProvider = AUTH_BEARER;
  let tokenUUID = extractTokenFromBearer(req.headers.authorization);
  // If no bearer specified, try with basic auth
  if (!tokenUUID) {
    loginProvider = AUTH_BASIC;
    tokenUUID = await extractTokenFromBasicAuth(req.headers.authorization);
  }
  // Get user from the token if found
  if (tokenUUID) {
    try {
      const user = await resolveUserByToken(tokenUUID);
      if (user) {
        return authenticateUser(req, user, loginProvider, tokenUUID);
      }
      return user;
    } catch (err) {
      logApp.error(`[OPENCTI] Authentication error ${tokenUUID}`, { error: err });
    }
  }
  // No auth, return undefined
  return undefined;
};

export const initAdmin = async (email, password, tokenValue) => {
  const existingAdmin = await findById(SYSTEM_USER, OPENCTI_ADMIN_UUID);
  if (existingAdmin) {
    // If admin user exists, just patch the fields
    const patch = {
      user_email: email,
      password: bcrypt.hashSync(password),
      api_token: tokenValue,
      external: true,
    };
    await patchAttribute(SYSTEM_USER, existingAdmin.id, ENTITY_TYPE_USER, patch);
  } else {
    const userToCreate = {
      internal_id: OPENCTI_ADMIN_UUID,
      external: true,
      user_email: email.toLowerCase(),
      name: 'admin',
      firstname: 'Admin',
      lastname: 'OpenCTI',
      description: 'Principal admin account',
      api_token: tokenValue,
      password,
    };
    await addUser(SYSTEM_USER, userToCreate);
  }
};

// region context
export const userCleanContext = async (user, userId) => {
  await delEditContext(user, userId);
  return storeLoadById(user, userId, ENTITY_TYPE_USER).then((userToReturn) => notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userToReturn, user));
};

export const userEditContext = async (user, userId, input) => {
  await setEditContext(user, userId, input);
  return storeLoadById(user, userId, ENTITY_TYPE_USER).then((userToReturn) => notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userToReturn, user));
};
// endregion
