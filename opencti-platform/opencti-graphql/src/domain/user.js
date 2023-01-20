import * as R from 'ramda';
import { map } from 'ramda';
import { authenticator } from 'otplib';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import { delEditContext, delUserContext, notify, setEditContext } from '../database/redis';
import { AuthenticationFailure, ForbiddenAccess, FunctionalError } from '../config/errors';
import { BUS_TOPICS, logApp, logAudit, OPENCTI_SESSION, PLATFORM_VERSION } from '../config/conf';
import {
  batchListThroughGetTo,
  createEntity,
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  listThroughGetFrom,
  listThroughGetTo,
  patchAttribute,
  updateAttribute,
} from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import {
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_USER,
} from '../schema/internalObject';
import {
  isInternalRelationship,
  RELATION_ACCESSES_TO,
  RELATION_HAS_CAPABILITY,
  RELATION_HAS_ROLE,
  RELATION_MEMBER_OF,
  RELATION_PARTICIPATE_TO,
} from '../schema/internalRelationship';
import { ABSTRACT_INTERNAL_RELATIONSHIP, OPENCTI_ADMIN_UUID } from '../schema/general';
import { findAll as allMarkings } from './markingDefinition';
import { findAll as findGroups } from './group';
import { generateStandardId } from '../schema/identifier';
import { elFindByIds, elLoadBy } from '../database/engine';
import { now } from '../utils/format';
import { findSessionsForUsers, killUserSessions, markSessionForRefresh } from '../database/session';
import {
  convertRelationToAction,
  IMPERSONATE_ACTION,
  LOGIN_ACTION,
  LOGOUT_ACTION,
  ROLE_DELETION,
  USER_CREATION,
  USER_DELETION,
} from '../config/audit';
import { buildPagination, isEmptyField, isNotEmptyField } from '../database/utils';
import {
  BYPASS,
  executionContext,
  INTERNAL_USERS,
  isBypassUser,
  isUserHasCapability,
  KNOWLEDGE_ORGANIZATION_RESTRICT,
  SETTINGS_SET_ACCESSES,
  SYSTEM_USER
} from '../utils/access';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../schema/stixDomainObject';
import { getEntityFromCache } from '../database/cache';

const BEARER = 'Bearer ';
const BASIC = 'Basic ';
const AUTH_BEARER = 'Bearer';
const AUTH_BASIC = 'BasicAuth';
export const STREAMAPI = 'STREAMAPI';
export const TAXIIAPI = 'TAXIIAPI';
export const ROLE_DEFAULT = 'Default';
const PLATFORM_ORGANIZATION = 'settings_platform_organization';

const roleSessionRefresh = async (context, user, roleId) => {
  const members = await listThroughGetFrom(context, user, [roleId], RELATION_HAS_ROLE, ENTITY_TYPE_USER);
  const sessions = await findSessionsForUsers(members.map((e) => e.internal_id));
  await Promise.all(sessions.map((s) => markSessionForRefresh(s.id)));
};

export const userSessionRefresh = async (userId) => {
  const sessions = await findSessionsForUsers([userId]);
  await Promise.all(sessions.map((s) => markSessionForRefresh(s.id)));
};

export const userWithOrigin = (req, user) => {
  // /!\ This metadata information is used in different ways
  // - In audit logs to identify the user
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

export const findById = async (context, user, userId) => {
  const data = await storeLoadById(context, user, userId, ENTITY_TYPE_USER);
  const withoutPassword = data ? R.dissoc('password', data) : data;
  return buildCompleteUser(context, withoutPassword);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_USER], args);
};

export const batchGroups = async (context, user, userId, opts = {}) => {
  return batchListThroughGetTo(context, user, userId, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP, opts);
};

export const batchUsers = async (context, user, userIds) => {
  const internalUserIds = Object.keys(INTERNAL_USERS);
  const userToFinds = R.uniq(userIds.filter((u) => isNotEmptyField(u)).filter((u) => !internalUserIds.includes(u)));
  const users = await elFindByIds(context, user, userToFinds, { toMap: true });
  return userIds.map((id) => INTERNAL_USERS[id] || users[id] || SYSTEM_USER);
};

export const batchOrganizations = async (context, user, userId, opts = {}) => {
  return batchListThroughGetTo(context, user, userId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION, opts);
};

export const batchRoles = async (context, user, userId) => {
  return batchListThroughGetTo(context, user, userId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, { paginate: false });
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

const getUserAndGlobalMarkings = async (context, userId, userGroups, capabilities) => {
  const groupIds = userGroups.map((r) => r.id);
  const userCapabilities = map((c) => c.name, capabilities);
  const shouldBypass = userCapabilities.includes(BYPASS) || userId === OPENCTI_ADMIN_UUID;
  const allMarkingsPromise = allMarkings(context, SYSTEM_USER).then((data) => R.map((i) => i.node, data.edges));
  let userMarkingsPromise;
  if (shouldBypass) {
    userMarkingsPromise = allMarkingsPromise;
  } else {
    userMarkingsPromise = listThroughGetTo(context, SYSTEM_USER, groupIds, RELATION_ACCESSES_TO, ENTITY_TYPE_MARKING_DEFINITION);
  }
  const [userMarkings, markings] = await Promise.all([userMarkingsPromise, allMarkingsPromise]);
  const computedMarkings = computeAvailableMarkings(userMarkings, markings);
  return { user: computedMarkings, all: markings };
};

export const getCapabilities = async (context, userId, isUserPlatform) => {
  const roles = await listThroughGetTo(context, SYSTEM_USER, userId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE);
  const roleIds = roles.map((r) => r.id);
  const capabilities = await listThroughGetTo(context, SYSTEM_USER, roleIds, RELATION_HAS_CAPABILITY, ENTITY_TYPE_CAPABILITY);
  if (userId === OPENCTI_ADMIN_UUID && !R.find(R.propEq('name', BYPASS))(capabilities)) {
    const id = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: BYPASS });
    capabilities.push({ id, standard_id: id, internal_id: id, name: BYPASS });
    return capabilities;
  }
  return isUserPlatform ? capabilities : capabilities.filter((c) => c.name !== KNOWLEDGE_ORGANIZATION_RESTRICT);
};

export const batchRoleCapabilities = async (context, user, roleId) => {
  return batchListThroughGetTo(context, user, roleId, RELATION_HAS_CAPABILITY, ENTITY_TYPE_CAPABILITY, { paginate: false });
};

export const findRoleById = (context, user, roleId) => {
  return storeLoadById(context, user, roleId, ENTITY_TYPE_ROLE);
};

export const findRoles = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_ROLE], args);
};

export const findCapabilities = (context, user, args) => {
  const finalArgs = R.assoc('orderBy', 'attribute_order', args);
  return listEntities(context, user, [ENTITY_TYPE_CAPABILITY], finalArgs);
};

export const roleDelete = async (context, user, roleId) => {
  await roleSessionRefresh(context, user, roleId);
  await deleteElementById(context, user, roleId, ENTITY_TYPE_ROLE);
  logAudit.info(user, ROLE_DELETION, { id: roleId });
  return roleId;
};

export const roleCleanContext = async (context, user, roleId) => {
  await delEditContext(user, roleId);
  return storeLoadById(context, user, roleId, ENTITY_TYPE_ROLE).then((role) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user);
  });
};

export const roleEditContext = async (context, user, roleId, input) => {
  await setEditContext(user, roleId, input);
  return storeLoadById(context, user, roleId, ENTITY_TYPE_ROLE).then((role) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user);
  });
};

const assignRoleToUser = async (context, user, userId, roleName) => {
  const generateToId = generateStandardId(ENTITY_TYPE_ROLE, { name: roleName });
  const assignInput = {
    fromId: userId,
    toId: generateToId,
    relationship_type: RELATION_HAS_ROLE,
  };
  return createRelation(context, user, assignInput);
};

export const assignOrganizationToUser = async (context, user, userId, organizationId) => {
  const assignInput = { fromId: userId, toId: organizationId, relationship_type: RELATION_PARTICIPATE_TO };
  await createRelation(context, user, assignInput);
  await userSessionRefresh(userId);
  return user;
};

export const assignOrganizationNameToUser = async (context, user, userId, organizationName) => {
  const organization = { name: organizationName, identity_class: 'organization' };
  const generateToId = generateStandardId(ENTITY_TYPE_IDENTITY_ORGANIZATION, organization);
  return assignOrganizationToUser(context, user, userId, generateToId);
};

const assignGroupToUser = async (context, user, userId, groupName) => {
  const generateToId = generateStandardId(ENTITY_TYPE_GROUP, { name: groupName });
  const assignInput = {
    fromId: userId,
    toId: generateToId,
    relationship_type: RELATION_MEMBER_OF,
  };
  const rel = await createRelation(context, user, assignInput);
  await userSessionRefresh(userId);
  return rel;
};

export const addUser = async (context, user, newUser) => {
  const userEmail = newUser.user_email.toLowerCase();
  const existingUser = await elLoadBy(context, SYSTEM_USER, 'user_email', userEmail, ENTITY_TYPE_USER);
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
  const userCreated = await createEntity(context, user, userToCreate, ENTITY_TYPE_USER);
  // Link to the roles
  let userRoles = newUser.roles ?? []; // Expected roles name
  const defaultRoles = await findRoles(context, user, { filters: [{ key: 'default_assignation', values: [true] }] });
  if (defaultRoles && defaultRoles.edges.length > 0) {
    userRoles = R.pipe(
      R.map((n) => n.node.name),
      R.append(userRoles),
      R.flatten
    )(defaultRoles.edges);
  }
  await Promise.all(R.map((role) => assignRoleToUser(context, user, userCreated.id, role), userRoles));
  // Link to organizations
  const userOrganizations = newUser.objectOrganization ?? [];
  await Promise.all(R.map((organization) => assignOrganizationToUser(context, user, userCreated.id, organization), userOrganizations));
  // Assign default groups to user
  const defaultGroups = await findGroups(context, user, { filters: [{ key: 'default_assignation', values: [true] }] });
  const relationGroups = defaultGroups.edges.map((e) => ({
    fromId: userCreated.id,
    toId: e.node.internal_id,
    relationship_type: RELATION_MEMBER_OF,
  }));
  await Promise.all(relationGroups.map((relation) => createRelation(context, user, relation)));
  // Audit log
  const groups = defaultGroups.edges.map((g) => ({ id: g.node.id, name: g.node.name }));
  logAudit.info(user, USER_CREATION, { user: userEmail, roles: userRoles, groups });
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].ADDED_TOPIC, userCreated, user);
};

export const roleEditField = async (context, user, roleId, input) => {
  const { element } = await updateAttribute(context, user, roleId, ENTITY_TYPE_ROLE, input);
  await roleSessionRefresh(context, user, roleId);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, element, user);
};

export const roleAddRelation = async (context, user, roleId, input) => {
  const role = await storeLoadById(context, user, roleId, ENTITY_TYPE_ROLE);
  if (!role) {
    throw FunctionalError(`Cannot add the relation, ${ENTITY_TYPE_ROLE} cannot be found.`);
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = R.assoc('fromId', roleId, input);
  const relationData = await createRelation(context, user, finalInput);
  await roleSessionRefresh(context, user, roleId);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, relationData, user);
};

export const roleDeleteRelation = async (context, user, roleId, toId, relationshipType) => {
  const role = await storeLoadById(context, user, roleId, ENTITY_TYPE_ROLE);
  if (!role) {
    throw FunctionalError('Cannot delete the relation, Role cannot be found.');
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(context, user, roleId, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  await roleSessionRefresh(context, user, roleId);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user);
};

// User related
export const userEditField = async (context, user, userId, inputs) => {
  for (let index = 0; index < inputs.length; index += 1) {
    const input = inputs[index];
    if (input.key === 'password') {
      input.value = [bcrypt.hashSync(R.head(input.value).toString())];
    }
  }
  const { element } = await updateAttribute(context, user, userId, ENTITY_TYPE_USER, inputs);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, element, user);
};

export const deleteBookmark = async (context, user, id) => {
  const currentUser = await storeLoadById(context, user, user.id, ENTITY_TYPE_USER);
  const currentBookmarks = currentUser.bookmarks ? currentUser.bookmarks : [];
  const newBookmarks = R.filter((n) => n.id !== id, currentBookmarks);
  await patchAttribute(context, user, user.id, ENTITY_TYPE_USER, { bookmarks: newBookmarks });
  return id;
};

export const bookmarks = async (context, user, types) => {
  const currentUser = await storeLoadById(context, user, user.id, ENTITY_TYPE_USER);
  const bookmarkList = types && types.length > 0
    ? R.filter((n) => R.includes(n.type, types), currentUser.bookmarks || [])
    : currentUser.bookmarks || [];
  const filteredBookmarks = [];
  // eslint-disable-next-line no-restricted-syntax
  for (const bookmark of bookmarkList) {
    const loadedBookmark = await storeLoadById(context, user, bookmark.id, bookmark.type);
    if (isNotEmptyField(loadedBookmark)) {
      filteredBookmarks.push(loadedBookmark);
    } else {
      await deleteBookmark(context, user, bookmark.id);
    }
  }
  return buildPagination(
    0,
    null,
    filteredBookmarks.map((n) => ({ node: n })),
    filteredBookmarks.length
  );
};

export const addBookmark = async (context, user, id, type) => {
  const currentUser = await storeLoadById(context, user, user.id, ENTITY_TYPE_USER);
  const currentBookmarks = currentUser.bookmarks ? currentUser.bookmarks : [];
  const newBookmarks = R.append(
    { id, type },
    R.filter((n) => n.id !== id, currentBookmarks)
  );
  await patchAttribute(context, user, user.id, ENTITY_TYPE_USER, { bookmarks: newBookmarks });
  return storeLoadById(context, user, id, type);
};

export const meEditField = (context, user, userId, inputs, password = null) => {
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
  return userEditField(context, user, userId, inputs);
};

export const userDelete = async (context, user, userId) => {
  await deleteElementById(context, user, userId, ENTITY_TYPE_USER);
  logAudit.info(user, USER_DELETION, { user: userId });
  await killUserSessions(userId);
  return userId;
};

export const userAddRelation = async (context, user, userId, input) => {
  const userData = await storeLoadById(context, user, userId, ENTITY_TYPE_USER);
  if (!userData) {
    throw FunctionalError(`Cannot add the relation, ${ENTITY_TYPE_USER} cannot be found.`);
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = R.assoc('fromId', userId, input);
  const relationData = await createRelation(context, user, finalInput);
  const operation = convertRelationToAction(input.relationship_type);
  logAudit.info(user, operation, { from: userId, to: input.toId, type: input.relationship_type });
  await userSessionRefresh(userId);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, relationData, user);
};

export const userDeleteRelation = async (context, user, targetUser, toId, relationshipType) => {
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(context, user, targetUser.id, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  const operation = convertRelationToAction(relationshipType, false);
  logAudit.info(user, operation, { from: targetUser.id, to: toId, type: relationshipType });
  await userSessionRefresh(targetUser.id);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, targetUser, user);
};

export const userIdDeleteRelation = async (context, user, userId, toId, relationshipType) => {
  const userData = await storeLoadById(context, user, userId, ENTITY_TYPE_USER);
  if (!userData) {
    throw FunctionalError('Cannot delete the relation, User cannot be found.');
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  return userDeleteRelation(context, user, userData, toId, relationshipType);
};

export const userDeleteOrganizationRelation = async (context, user, userId, toId) => {
  const targetUser = await storeLoadById(context, user, userId, ENTITY_TYPE_USER);
  if (!targetUser) {
    throw FunctionalError('Cannot delete the relation, User cannot be found.');
  }
  await deleteRelationsByFromAndTo(context, user, userId, toId, RELATION_PARTICIPATE_TO, ABSTRACT_INTERNAL_RELATIONSHIP);
  const operation = convertRelationToAction(RELATION_PARTICIPATE_TO, false);
  logAudit.info(user, operation, { from: userId, to: toId, type: RELATION_PARTICIPATE_TO });
  await userSessionRefresh(userId);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, targetUser, user);
};

export const loginFromProvider = async (userInfo, opts = {}) => {
  const { providerRoles = [], providerGroups = [], providerOrganizations = [] } = opts;
  const context = executionContext('login_provider');
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const listOpts = { paginate: false };
  const { email, name: providedName, firstname, lastname } = userInfo;
  if (isEmptyField(email)) {
    throw Error('User email not provided');
  }
  const name = isEmptyField(providedName) ? email : providedName;
  const user = await elLoadBy(context, SYSTEM_USER, 'user_email', email, ENTITY_TYPE_USER);
  if (!user) {
    // If user doesn't exist, create it. Providers are trusted
    const newUser = { name, firstname, lastname, user_email: email.toLowerCase(), external: true };
    return addUser(context, SYSTEM_USER, newUser).then(() => {
      // After user creation, reapply login to manage roles and groups
      return loginFromProvider(userInfo, opts);
    });
  }
  // Update the basic information
  const patch = { name, firstname, lastname, external: true };
  await patchAttribute(context, SYSTEM_USER, user.id, ENTITY_TYPE_USER, patch);
  // region Update the roles
  // If roles are specified here, that overwrite the default assignation
  if (providerRoles.length > 0) {
    // 01 - Delete all roles from the user
    const userRoles = await listThroughGetTo(context, SYSTEM_USER, user.id, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, listOpts);
    const deleteRoles = userRoles.filter((o) => !providerRoles.includes(o.name));
    for (let index = 0; index < deleteRoles.length; index += 1) {
      const userRole = userRoles[index];
      await userDeleteRelation(context, SYSTEM_USER, user, userRole.id, RELATION_HAS_ROLE);
    }
    // 02 - Create roles from providers
    const createRoles = providerRoles.filter((n) => !userRoles.map((o) => o.name).includes(n));
    if (createRoles.length > 0) {
      const rolesCreation = createRoles.map((role) => assignRoleToUser(context, SYSTEM_USER, user.id, role));
      await Promise.all(rolesCreation);
    }
  }
  // endregion
  // region Update the groups
  // If groups are specified here, that overwrite the default assignation
  if (providerGroups.length > 0) {
    // 01 - Delete all groups from the user
    const userGroups = await listThroughGetTo(context, SYSTEM_USER, user.id, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP, listOpts);
    const deleteGroups = userGroups.filter((o) => !providerGroups.includes(o.name));
    for (let index = 0; index < deleteGroups.length; index += 1) {
      const userGroup = userGroups[index];
      await userDeleteRelation(context, SYSTEM_USER, user, userGroup.id, RELATION_MEMBER_OF);
    }
    // 02 - Create groups from providers
    const createGroups = providerGroups.filter((n) => !userGroups.map((o) => o.name).includes(n));
    if (createGroups.length > 0) {
      const groupsCreation = createGroups.map((group) => assignGroupToUser(context, SYSTEM_USER, user.id, group));
      await Promise.all(groupsCreation);
    }
  }
  // endregion
  // region Update the organizations
  // If organizations are specified here, that overwrite the default assignation
  if (providerOrganizations.length > 0) {
    // 01 - Delete all organizations no longer assign to the user
    const userOrganizations = await listThroughGetTo(context, SYSTEM_USER, user.id, RELATION_PARTICIPATE_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION, listOpts);
    const deleteOrganizations = userOrganizations.filter((o) => !providerOrganizations.includes(o.name));
    for (let index = 0; index < deleteOrganizations.length; index += 1) {
      const userOrganization = deleteOrganizations[index];
      await userDeleteRelation(context, SYSTEM_USER, user, userOrganization.id, RELATION_PARTICIPATE_TO);
    }
    // 02 - Create organizations if needed
    const createOrganizations = providerOrganizations.filter((n) => !userOrganizations.map((o) => o.name).includes(n));
    if (createOrganizations.length > 0) {
      const organizationsCreation = createOrganizations.map((orga) => {
        if (orga === PLATFORM_ORGANIZATION && settings.platform_organization) {
          return assignOrganizationToUser(context, SYSTEM_USER, user.id, settings.platform_organization);
        }
        return assignOrganizationNameToUser(context, SYSTEM_USER, user.id, orga);
      });
      await Promise.all(organizationsCreation);
    }
  }
  // endregion
  return user;
};

export const login = async (email, password) => {
  const context = executionContext('login');
  const user = await elLoadBy(context, SYSTEM_USER, 'user_email', email, ENTITY_TYPE_USER);
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

export const otpUserActivation = async (context, user, { secret, code }) => {
  const isValidated = authenticator.check(code, secret);
  if (isValidated) {
    const uri = authenticator.keyuri(user.user_email, 'OpenCTI', secret);
    const patch = { otp_activated: true, otp_secret: secret, otp_qr: uri };
    const { element } = await patchAttribute(context, user, user.id, ENTITY_TYPE_USER, patch);
    context.req.session.user.otp_validated = isValidated;
    context.req.session.user.otp_activated = true;
    return element;
  }
  throw AuthenticationFailure();
};

export const otpUserDeactivation = async (context, user, id) => {
  const patch = { otp_activated: false, otp_secret: '', otp_qr: '' };
  const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_USER, patch);
  return element;
};

export const otpUserLogin = async (req, user, { code }) => {
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

export const logout = async (context, user, req, res) => {
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

const buildSessionUser = (origin, impersonate, provider, settings) => {
  const user = impersonate ?? origin;
  return {
    id: user.id,
    individual_id: user.individual_id,
    session_creation: now(),
    session_password: user.password,
    api_token: user.api_token,
    internal_id: user.internal_id,
    user_email: user.user_email,
    otp_activated: user.otp_activated,
    otp_validated: user.otp_validated || (!user.otp_activated && !settings.otp_mandatory) || provider === AUTH_BEARER, // 2FA is implicitly validated when login from token
    otp_secret: user.otp_secret,
    otp_mandatory: settings.otp_mandatory,
    name: user.name,
    external: user.external,
    login_provider: provider,
    impersonate: impersonate !== undefined,
    capabilities: user.capabilities.map((c) => ({ id: c.id, internal_id: c.internal_id, name: c.name })),
    organizations: user.organizations,
    allowed_organizations: user.allowed_organizations,
    inside_platform_organization: user.inside_platform_organization,
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
    session_version: PLATFORM_VERSION
  };
};

const buildCompleteUser = async (context, client) => {
  if (!client) {
    return undefined;
  }
  const batchOpts = { batched: false, paginate: false };
  const args = { filters: [{ key: 'contact_information', values: [client.user_email] }], connectionFormat: false };
  const individualsPromise = listEntities(context, SYSTEM_USER, [ENTITY_TYPE_IDENTITY_INDIVIDUAL], args);
  const organizationsPromise = batchOrganizations(context, SYSTEM_USER, client.id, { ...batchOpts, withInferences: false });
  const userGroupsPromise = listThroughGetTo(context, SYSTEM_USER, client.id, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP);
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const allowed_organizations = await batchOrganizations(context, SYSTEM_USER, client.id, batchOpts);
  const userOrganizations = allowed_organizations.map((m) => m.internal_id);
  const isUserPlatform = settings.platform_organization ? userOrganizations.includes(settings.platform_organization) : true;
  const capabilities = await getCapabilities(context, client.id, isUserPlatform);
  const [individuals, organizations, groups] = await Promise.all([individualsPromise, organizationsPromise, userGroupsPromise]);
  const marking = await getUserAndGlobalMarkings(context, client.id, groups, capabilities);
  const individualId = individuals.length > 0 ? R.head(individuals).id : undefined;
  return {
    ...client,
    capabilities,
    groups,
    organizations,
    allowed_organizations,
    individual_id: individualId,
    inside_platform_organization: isUserPlatform,
    allowed_marking: marking.user,
    all_marking: marking.all
  };
};

export const resolveUserById = async (context, id) => {
  if (INTERNAL_USERS[id]) return INTERNAL_USERS[id];
  const client = await storeLoadById(context, SYSTEM_USER, id, ENTITY_TYPE_USER);
  return buildCompleteUser(context, client);
};

const resolveUserByToken = async (context, tokenValue) => {
  const client = await elLoadBy(context, SYSTEM_USER, 'api_token', tokenValue, ENTITY_TYPE_USER);
  return buildCompleteUser(context, client);
};

export const userRenewToken = async (context, user, userId) => {
  const patch = { api_token: uuid() };
  await patchAttribute(context, user, userId, ENTITY_TYPE_USER, patch);
  return storeLoadById(context, user, userId, ENTITY_TYPE_USER);
};

export const internalAuthenticateUser = async (context, req, user, provider, token) => {
  let impersonate;
  const logged = await buildCompleteUser(context, user);
  const applicantId = req.headers['opencti-applicant-id'];
  if (isNotEmptyField(applicantId) && logged.id !== applicantId) {
    if (isBypassUser(logged)) {
      const applicantUser = await resolveUserById(context, applicantId);
      if (isEmptyField(applicantUser)) {
        logApp.warn(`User ${applicantId} cant be impersonate (not exists)`);
      } else {
        logAudit.info(applicantUser, IMPERSONATE_ACTION, { from: user.id, to: applicantUser.id });
        impersonate = applicantUser;
      }
    } else {
      logAudit.error(user, IMPERSONATE_ACTION, { to: applicantId });
    }
  }
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const sessionUser = buildSessionUser(logged, impersonate, provider, settings);
  const hasSetAccessCapability = isUserHasCapability(logged, SETTINGS_SET_ACCESSES);
  if (!hasSetAccessCapability && settings.platform_organization && logged.organizations.length === 0) {
    throw AuthenticationFailure('You can\'t login without an organization');
  }
  req.session.user = sessionUser;
  req.session.session_provider = { provider, token };
  req.session.session_refresh = false;
  return sessionUser;
};

export const authenticateUser = async (context, req, user, provider, token = '') => {
  // Build the user session with only required fields
  logAudit.info(userWithOrigin(req, user), LOGIN_ACTION, { provider });
  return internalAuthenticateUser(context, req, user, provider, token);
};

export const authenticateUserFromRequest = async (context, req, res) => {
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
        await logout(context, auth, req, res);
        return authenticateUserFromRequest(context, req, res);
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
        await logout(context, auth, req, res);
        return authenticateUserFromRequest(context, req, res);
      }
    }
    // Other providers doesn't need specific validation, session management is enough
    // For impersonate auth, the applicant id must match the session
    const applicantId = req.headers['opencti-applicant-id'];
    const isNotSameUser = auth.id !== applicantId;
    const isImpersonateChange = auth.impersonate && isNotSameUser;
    const isNowImpersonate = isNotSameUser && !auth.impersonate && isBypassUser(auth) && applicantId;
    if (isImpersonateChange || isNowImpersonate) {
      // Impersonate doesn't match, kill the current session and try to re auth
      await logout(context, auth, req, res);
      return authenticateUserFromRequest(context, req, res);
    }
    // If session is marked for refresh, reload the user data in the session
    // If session is old by a past application version, make a refresh
    if (auth.session_version !== PLATFORM_VERSION || req.session.session_refresh) {
      const { session_provider } = req.session;
      const { provider: userProvider, token: userToken } = session_provider;
      return internalAuthenticateUser(context, req, auth, userProvider, userToken);
    }
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
      const user = await resolveUserByToken(context, tokenUUID);
      if (user) {
        return await authenticateUser(context, req, user, loginProvider, tokenUUID);
      }
      return user;
    } catch (err) {
      logApp.error(`[OPENCTI] Authentication error ${tokenUUID}`, { error: err });
    }
  }
  // No auth, return undefined
  return undefined;
};

export const initAdmin = async (context, email, password, tokenValue) => {
  const existingAdmin = await findById(context, SYSTEM_USER, OPENCTI_ADMIN_UUID);
  if (existingAdmin) {
    // If admin user exists, just patch the fields
    const patch = {
      user_email: email,
      password: bcrypt.hashSync(password),
      api_token: tokenValue,
      external: true,
    };
    await patchAttribute(context, SYSTEM_USER, existingAdmin.id, ENTITY_TYPE_USER, patch);
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
    await addUser(context, SYSTEM_USER, userToCreate);
  }
};

// region context
export const userCleanContext = async (context, user, userId) => {
  await delEditContext(user, userId);
  return storeLoadById(context, user, userId, ENTITY_TYPE_USER).then((userToReturn) => notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userToReturn, user));
};

export const userEditContext = async (context, user, userId, input) => {
  await setEditContext(user, userId, input);
  return storeLoadById(context, user, userId, ENTITY_TYPE_USER).then((userToReturn) => notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userToReturn, user));
};
// endregion
