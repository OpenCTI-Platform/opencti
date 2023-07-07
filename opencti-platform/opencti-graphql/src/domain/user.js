import * as R from 'ramda';
import { uniq } from 'ramda';
import { authenticator } from 'otplib';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import { delEditContext, delUserContext, notify, setEditContext } from '../database/redis';
import { AuthenticationFailure, ForbiddenAccess, FunctionalError } from '../config/errors';
import { BUS_TOPICS, logApp, OPENCTI_SESSION, PLATFORM_VERSION } from '../config/conf';
import {
  batchListThroughGetTo,
  createEntity,
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  listThroughGetTo,
  patchAttribute,
  updateAttribute, updatedInputsToData,
} from '../database/middleware';
import {
  listAllEntities,
  listAllEntitiesForFilter,
  listAllRelations,
  listEntities,
  storeLoadById
} from '../database/middleware-loader';
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
import { defaultMarkingDefinitionsFromGroups, findAll as findGroups } from './group';
import { generateStandardId } from '../schema/identifier';
import { elFindByIds, elLoadBy } from '../database/engine';
import { now } from '../utils/format';
import { findSessionsForUsers, killUserSessions, markSessionForRefresh } from '../database/session';
import { buildPagination, extractEntityRepresentative, isEmptyField, isNotEmptyField } from '../database/utils';
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
import { getEntitiesListFromCache, getEntityFromCache } from '../database/cache';
import { addIndividual } from './individual';
import { ASSIGNEE_FILTER, CREATOR_FILTER, PARTICIPANT_FILTER } from '../utils/filtering';
import { publishUserAction } from '../listener/UserActionListener';
import { addGroup } from './grant';

const BEARER = 'Bearer ';
const BASIC = 'Basic ';
const AUTH_BEARER = 'Bearer';
const AUTH_BASIC = 'BasicAuth';
export const STREAMAPI = 'STREAMAPI';
export const TAXIIAPI = 'TAXIIAPI';
export const ROLE_DEFAULT = 'Default';
const PLATFORM_ORGANIZATION = 'settings_platform_organization';

const roleSessionRefresh = async (context, user, roleId) => {
  // Get all groups that have this role
  const groupsRoles = await listAllRelations(context, user, RELATION_HAS_ROLE, { toId: roleId, fromTypes: [ENTITY_TYPE_GROUP] });
  const groupIds = groupsRoles.map((group) => group.fromId);
  // Get all users for groups
  const usersGroups = await listAllRelations(context, user, RELATION_MEMBER_OF, { toId: groupIds, toTypes: [ENTITY_TYPE_GROUP] });
  const userIds = R.uniq(usersGroups.map((u) => u.fromId));
  // Mark for refresh all impacted sessions
  const sessions = await findSessionsForUsers(userIds);
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
    socket: 'query',
    ip: req?.ip,
    user_id: user?.id,
    group_ids: user?.group_ids,
    organization_ids: user?.organizations?.map((o) => o.internal_id) ?? [],
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

export const findCreators = (context, user, args) => {
  const { entityTypes = [] } = args;
  return listAllEntitiesForFilter(context, user, CREATOR_FILTER, ENTITY_TYPE_USER, { ...args, types: entityTypes });
};

export const findAssignees = (context, user, args) => {
  const { entityTypes = [] } = args;
  return listAllEntitiesForFilter(context, user, ASSIGNEE_FILTER, ENTITY_TYPE_USER, { ...args, types: entityTypes });
};
export const findParticipants = (context, user, args) => {
  const { entityTypes = [] } = args;
  return listAllEntitiesForFilter(context, user, PARTICIPANT_FILTER, ENTITY_TYPE_USER, { ...args, types: entityTypes });
};

export const findAllMembers = (context, user, args) => {
  const { entityTypes = null } = args;
  const types = entityTypes || [ENTITY_TYPE_USER, ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_GROUP];
  return listEntities(context, user, types, args);
};

export const batchGroups = async (context, user, userId, opts = {}) => {
  return batchListThroughGetTo(context, user, userId, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP, opts);
};

const internalUserIds = Object.keys(INTERNAL_USERS);
export const batchCreator = async (context, user, userIds) => {
  const userToFinds = R.uniq(userIds.filter((u) => isNotEmptyField(u)).filter((u) => !internalUserIds.includes(u)));
  const users = await elFindByIds(context, user, userToFinds, { toMap: true });
  return userIds.map((id) => INTERNAL_USERS[id] || users[id] || SYSTEM_USER);
};

export const batchCreators = async (context, user, userListIds) => {
  const userIds = userListIds.map((u) => (Array.isArray(u) ? u : [u]));
  const allUserIds = userIds.flat();
  const userToFinds = R.uniq(allUserIds.filter((u) => isNotEmptyField(u)).filter((u) => !internalUserIds.includes(u)));
  const users = await elFindByIds(context, user, userToFinds, { toMap: true });
  return userIds.map((ids) => ids.map((id) => INTERNAL_USERS[id] || users[id] || SYSTEM_USER));
};

export const batchOrganizations = async (context, user, userId, opts = {}) => {
  return batchListThroughGetTo(context, user, userId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION, opts);
};

export const batchRolesForGroups = async (context, user, groupId, opts = {}) => {
  return batchListThroughGetTo(context, user, groupId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, { ...opts, paginate: false });
};

export const batchRolesForUsers = async (context, user, userIds, opts = {}) => {
  // Get all groups for users
  const usersGroups = await listAllRelations(context, user, RELATION_MEMBER_OF, { fromId: userIds, toTypes: [ENTITY_TYPE_GROUP] });
  const groupIds = [];
  const usersWithGroups = {};
  usersGroups.forEach((userGroup) => {
    if (!groupIds.includes(userGroup.toId)) {
      groupIds.push(userGroup.toId);
    }
    if (usersWithGroups[userGroup.fromId]) {
      usersWithGroups[userGroup.fromId] = [...usersWithGroups[userGroup.fromId], userGroup.toId];
    } else {
      usersWithGroups[userGroup.fromId] = [userGroup.toId];
    }
  });
  // Get all roles for groups
  const roleIds = [];
  const groupWithRoles = {};
  const groupsRoles = await listAllRelations(context, user, RELATION_HAS_ROLE, { fromId: groupIds, toTypes: [ENTITY_TYPE_ROLE] });
  groupsRoles.forEach((groupRole) => {
    if (!roleIds.includes(groupRole.toId)) {
      roleIds.push(groupRole.toId);
    }
    if (groupWithRoles[groupRole.fromId]) {
      groupWithRoles[groupRole.fromId] = [...groupWithRoles[groupRole.fromId], groupRole.toId];
    } else {
      groupWithRoles[groupRole.fromId] = [groupRole.toId];
    }
  });
  const roles = await listAllEntities(context, user, [ENTITY_TYPE_ROLE], { ...opts, ids: roleIds });
  return userIds.map((u) => {
    const groups = usersWithGroups[u] ?? [];
    const idRoles = uniq(groups.map((g) => groupWithRoles[g] ?? []).flat());
    return roles.filter((t) => idRoles.includes(t.internal_id));
  });
};

export const computeAvailableMarkings = (markings, all) => {
  const computedMarkings = [];
  for (let index = 0; index < markings.length; index += 1) {
    const mark = markings[index];
    // Find all marking of same type with rank <=
    const { id } = mark;
    const findMarking = R.find((m) => m.id === id, all);
    computedMarkings.push(findMarking);
    const { x_opencti_order: order, definition_type: type } = findMarking ?? {};
    const matchingMarkings = R.filter((m) => {
      return id !== m.id && m.definition_type === type && m.x_opencti_order <= order;
    }, all);
    computedMarkings.push(...matchingMarkings);
  }
  return R.uniqBy((m) => m?.id ?? '', computedMarkings);
};

const getUserAndGlobalMarkings = async (context, userId, userGroups, capabilities) => {
  const groupIds = userGroups.map((r) => r.id);
  const userCapabilities = capabilities.map((c) => c.name);
  const shouldBypass = userCapabilities.includes(BYPASS) || userId === OPENCTI_ADMIN_UUID;
  const allMarkingsPromise = getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  let userMarkingsPromise;
  if (shouldBypass) {
    userMarkingsPromise = allMarkingsPromise;
  } else {
    userMarkingsPromise = listThroughGetTo(context, SYSTEM_USER, groupIds, RELATION_ACCESSES_TO, ENTITY_TYPE_MARKING_DEFINITION);
  }
  const [userMarkings, markings, defaultMarkings] = await Promise.all([userMarkingsPromise, allMarkingsPromise, defaultMarkingDefinitionsFromGroups(context, groupIds)]);
  const computedMarkings = computeAvailableMarkings(userMarkings, markings);
  return { user: computedMarkings, all: markings, default: defaultMarkings };
};

export const getRoles = async (context, userGroups) => {
  const groupIds = userGroups.map((r) => r.id);
  return listThroughGetTo(context, SYSTEM_USER, groupIds, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE);
};

export const getCapabilities = async (context, userId, userRoles, isUserPlatform) => {
  const roleIds = userRoles.map((r) => r.id);
  const capabilities = R.uniq(await listThroughGetTo(context, SYSTEM_USER, roleIds, RELATION_HAS_CAPABILITY, ENTITY_TYPE_CAPABILITY));
  // Force push the bypass for default admin
  const withoutBypass = !capabilities.some((c) => c.name === BYPASS);
  if (userId === OPENCTI_ADMIN_UUID && withoutBypass) {
    const id = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: BYPASS });
    capabilities.push({ id, standard_id: id, internal_id: id, name: BYPASS });
    return capabilities;
  }
  return isUserPlatform ? capabilities : capabilities.filter((c) => c.name !== KNOWLEDGE_ORGANIZATION_RESTRICT);
};

export const batchRoleCapabilities = async (context, user, roleId) => {
  return batchListThroughGetTo(context, user, roleId, RELATION_HAS_CAPABILITY, ENTITY_TYPE_CAPABILITY, { paginate: false });
};

export const getDefaultHiddenTypes = async (context, userId, userRoles) => {
  let userDefaultHiddenTypes = userRoles.map((role) => role.default_hidden_types).flat();
  userDefaultHiddenTypes = uniq(userDefaultHiddenTypes.filter((type) => type !== undefined));
  return userDefaultHiddenTypes;
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
  const deleted = await deleteElementById(context, user, roleId, ENTITY_TYPE_ROLE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes role \`${deleted.name}\``,
    context_data: { id: roleId, entity_type: ENTITY_TYPE_ROLE, input: deleted }
  });
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

export const assignOrganizationToUser = async (context, user, userId, organizationId) => {
  const input = { fromId: userId, toId: organizationId, relationship_type: RELATION_PARTICIPATE_TO };
  const created = await createRelation(context, user, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds ${created.toType} \`${extractEntityRepresentative(created.to)}\` to user \`${created.from.user_email}\``,
    context_data: { id: organizationId, entity_type: ENTITY_TYPE_USER, input }
  });
  await userSessionRefresh(userId);
  return user;
};

export const assignOrganizationNameToUser = async (context, user, userId, organizationName) => {
  const organization = { name: organizationName, identity_class: 'organization' };
  const generateToId = generateStandardId(ENTITY_TYPE_IDENTITY_ORGANIZATION, organization);
  return assignOrganizationToUser(context, user, userId, generateToId);
};

export const assignGroupToUser = async (context, user, userId, groupName) => {
  // No need for audit log here, only use for provider login
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

export const checkPasswordInlinePolicy = (context, policy, password) => {
  const {
    password_policy_min_length,
    password_policy_max_length,
    password_policy_min_symbols,
    password_policy_min_numbers,
    password_policy_min_words,
    password_policy_min_lowercase,
    password_policy_min_uppercase
  } = policy;
  const errors = [];
  if (isEmptyField(password)) {
    errors.push('required');
  }
  if (password_policy_min_length && password_policy_min_length > 0) {
    if (password.length < password_policy_min_length) {
      errors.push(`size must be >= ${password_policy_min_length}`);
    }
  }
  if (password_policy_max_length && password_policy_max_length > 0) {
    if (password.length > password_policy_max_length) {
      errors.push(`size must be <= ${password_policy_max_length}`);
    }
  }
  if (password_policy_min_symbols && password_policy_min_symbols > 0) {
    if ((password.match(/[^a-zA-Z0-9]/g) ?? []).length < password_policy_min_symbols) {
      errors.push(`number of symbols must be >= ${password_policy_min_symbols}`);
    }
  }
  if (password_policy_min_numbers && password_policy_min_numbers > 0) {
    if ((password.match(/[0-9]/g) ?? []).length < password_policy_min_numbers) {
      errors.push(`number of digits must be >= ${password_policy_min_numbers}`);
    }
  }
  if (password_policy_min_words && password_policy_min_words > 0) {
    if (password.split(/[|, _-]/).length < password_policy_min_words) {
      errors.push(`number of words must be >= ${password_policy_min_words}`);
    }
  }
  if (password_policy_min_lowercase && password_policy_min_lowercase > 0) {
    if ((password.match(/[a-z]/g) ?? []).length < password_policy_min_lowercase) {
      errors.push(`number of lower chars must be >= ${password_policy_min_lowercase}`);
    }
  }
  if (password_policy_min_uppercase && password_policy_min_uppercase > 0) {
    if ((password.match(/[A-Z]/g) ?? []).length < password_policy_min_uppercase) {
      errors.push(`number of upper chars must be >= ${password_policy_min_uppercase}`);
    }
  }
  return errors;
};

export const checkPasswordFromPolicy = async (context, password) => {
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const errors = checkPasswordInlinePolicy(context, settings, password);
  if (errors.length > 0) {
    throw FunctionalError(`Invalid password: ${errors.join(', ')}`);
  }
};

export const isPasswordPoliciesInvalid = async (context, password) => {
  return checkPasswordFromPolicy(context, password).then(() => false).catch(() => true);
};

export const addUser = async (context, user, newUser) => {
  const userEmail = newUser.user_email.toLowerCase();
  const existingUser = await elLoadBy(context, SYSTEM_USER, 'user_email', userEmail, ENTITY_TYPE_USER);
  if (existingUser) {
    throw FunctionalError('User already exists', { email: userEmail });
  }
  // Create the user
  let userPassword = newUser.password;
  // If user is external and password is not specified, associate a random password
  if (newUser.external === true && isEmptyField(userPassword)) {
    userPassword = uuid();
  } else { // If local user, check the password policy
    await checkPasswordFromPolicy(context, userPassword);
  }
  const userToCreate = R.pipe(
    R.assoc('user_email', userEmail),
    R.assoc('api_token', newUser.api_token ? newUser.api_token : uuid()),
    R.assoc('password', bcrypt.hashSync(userPassword)),
    R.assoc('theme', newUser.theme ? newUser.theme : 'default'),
    R.assoc('language', newUser.language ? newUser.language : 'auto'),
    R.assoc('external', newUser.external ? newUser.external : false),
    R.dissoc('roles')
  )(newUser);
  const { element, isCreation } = await createEntity(context, user, userToCreate, ENTITY_TYPE_USER, { complete: true });
  // Link to organizations
  const userOrganizations = newUser.objectOrganization ?? [];
  await Promise.all(R.map((organization) => assignOrganizationToUser(context, user, element.id, organization), userOrganizations));
  // Assign default groups to user
  const defaultGroups = await findGroups(context, user, { filters: [{ key: 'default_assignation', values: [true] }] });
  const relationGroups = defaultGroups.edges.map((e) => ({
    fromId: element.id,
    toId: e.node.internal_id,
    relationship_type: RELATION_MEMBER_OF,
  }));
  await Promise.all(relationGroups.map((relation) => createRelation(context, user, relation)));
  // Audit log
  if (isCreation) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates user \`${userEmail}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_USER, input: newUser }
    });
  }
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].ADDED_TOPIC, element, user);
};

export const roleEditField = async (context, user, roleId, input) => {
  const { element } = await updateAttribute(context, user, roleId, ENTITY_TYPE_ROLE, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for role \`${element.name}\``,
    context_data: { id: roleId, entity_type: ENTITY_TYPE_ROLE, input }
  });
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
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds ${relationData.to.entity_type} \`${extractEntityRepresentative(relationData.to)}\` for role \`${role.name}\``,
    context_data: { id: roleId, entity_type: ENTITY_TYPE_ROLE, input: finalInput }
  });
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
  const deleted = await deleteRelationsByFromAndTo(context, user, roleId, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  const input = { fromId: roleId, toId, relationship_type: relationshipType };
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `removes ${deleted.to.entity_type} \`${extractEntityRepresentative(deleted.to)}\` for role \`${role.name}\``,
    context_data: { id: roleId, entity_type: ENTITY_TYPE_ROLE, input }
  });
  await roleSessionRefresh(context, user, roleId);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user);
};

// User related
export const userEditField = async (context, user, userId, inputs) => {
  for (let index = 0; index < inputs.length; index += 1) {
    const input = inputs[index];
    if (input.key === 'password') {
      const userPassword = R.head(input.value).toString();
      await checkPasswordFromPolicy(context, userPassword);
      input.value = [bcrypt.hashSync(userPassword)];
    }
  }
  const { element } = await updateAttribute(context, user, userId, ENTITY_TYPE_USER, inputs);
  const input = updatedInputsToData(element, inputs);
  const personalUpdate = user.id === userId;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: personalUpdate ? 'extended' : 'administration',
    message: `updates \`${inputs.map((i) => i.key).join(', ')}\` for ${personalUpdate ? '`themselves`' : `user \`${element.user_email}\``}`,
    context_data: { id: userId, entity_type: ENTITY_TYPE_USER, input }
  });
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

const PROTECTED_USER_ATTRIBUTES = ['api_token', 'external'];
const PROTECTED_EXTERNAL_ATTRIBUTES = ['user_email', 'user_name'];
export const meEditField = async (context, user, userId, inputs, password = null) => {
  const input = R.head(inputs);
  const { key } = input;
  // Check if field can be updated by the user
  if (PROTECTED_USER_ATTRIBUTES.includes(key)) {
    throw ForbiddenAccess();
  }
  // If the user is external, some extra attributes must be protected
  if (user.external && PROTECTED_EXTERNAL_ATTRIBUTES.includes(key)) {
    throw ForbiddenAccess();
  }
  // Check password confirmation in case of password change
  if (key === 'password') {
    const dbPassword = user.session_password;
    const match = bcrypt.compareSync(password, dbPassword);
    if (!match) {
      throw FunctionalError('The current password you have provided is not valid');
    }
  }
  return userEditField(context, user, userId, inputs);
};

export const userDelete = async (context, user, userId) => {
  const deleted = await deleteElementById(context, user, userId, ENTITY_TYPE_USER);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes user \`${deleted.user_email}\``,
    context_data: { id: userId, entity_type: ENTITY_TYPE_USER, input: deleted }
  });
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
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds ${relationData.toType} \`${extractEntityRepresentative(relationData.to)}\` for user \`${userData.user_email}\``,
    context_data: { id: userId, entity_type: ENTITY_TYPE_USER, input: finalInput }
  });
  await userSessionRefresh(userId);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, relationData, user);
};

export const userDeleteRelation = async (context, user, targetUser, toId, relationshipType) => {
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  const { to } = await deleteRelationsByFromAndTo(context, user, targetUser.id, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  const input = { relationship_type: relationshipType, toId };
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `removes ${to.entity_type} \`${extractEntityRepresentative(to)}\` for user \`${targetUser.user_email}\``,
    context_data: { id: targetUser.id, entity_type: ENTITY_TYPE_USER, input }
  });
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
  const { to } = await deleteRelationsByFromAndTo(context, user, userId, toId, RELATION_PARTICIPATE_TO, ABSTRACT_INTERNAL_RELATIONSHIP);
  const input = { relationship_type: RELATION_PARTICIPATE_TO, toId };
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `removes ${to.entity_type} \`${extractEntityRepresentative(to)}\` for user \`${targetUser.user_email}\``,
    context_data: { id: userId, entity_type: ENTITY_TYPE_USER, input }
  });
  await userSessionRefresh(userId);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, targetUser, user);
};

export const loginFromProvider = async (userInfo, opts = {}) => {
  const { providerGroups = [], providerOrganizations = [], autoCreateGroup = false } = opts;
  const context = executionContext('login_provider');
  // region test the groups existence and eventually auto create groups
  if (providerGroups.length > 0) {
    const providerGroupsIds = providerGroups.map((groupName) => generateStandardId(ENTITY_TYPE_GROUP, { name: groupName }));
    const foundGroups = await findGroups(context, SYSTEM_USER, { filters: [{ key: 'standard_id', values: providerGroupsIds }] });
    const foundGroupsNames = foundGroups.edges.map((group) => group.node.name);
    const newGroupsToCreate = [];
    providerGroups.forEach((groupName) => {
      if (!foundGroupsNames.includes(groupName)) {
        if (!autoCreateGroup) {
          throw Error('[SSO] Can\'t login. The user has groups that don\'t exist and auto_create_group = false.');
        } else {
          newGroupsToCreate.push(addGroup(context, SYSTEM_USER, { name: groupName }));
        }
      }
    });
    await Promise.all(newGroupsToCreate);
  }
  // endregion
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
  // region Update the groups
  // If groups are specified here, that overwrite the default assignation
  if (providerGroups.length > 0) {
    // 01 - Delete all groups relation from the user
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

export const userAddIndividual = async (context, user) => {
  const individualInput = { name: user.name, contact_information: user.user_email };
  // We need to bypass validation here has we maybe not setup all require fields
  const individual = await addIndividual(context, user, individualInput, { bypassValidation: true });
  // Need to check that in the future, seems that the queryAsAdmin in test fails without that
  if (context.req?.session) {
    context.req.session.user.individual_id = individual.id;
  }
  await userSessionRefresh(user.internal_id);
  return individual;
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

export const logout = async (context, user, req, res, regeneration = false) => {
  const withOrigin = userWithOrigin(req, user);
  if (regeneration === false) {
    await publishUserAction({
      user: withOrigin,
      event_type: 'authentication',
      event_access: 'administration',
      event_scope: 'logout',
      context_data: undefined
    });
  }
  await delUserContext(user);
  return new Promise((resolve) => {
    res.clearCookie(OPENCTI_SESSION);
    req.session.regenerate(() => {
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
    otp_activated: user.otp_activated || provider === AUTH_BEARER,
    otp_validated: user.otp_validated || (!user.otp_activated && !settings.otp_mandatory) || provider === AUTH_BEARER, // 2FA is implicitly validated when login from token
    otp_secret: user.otp_secret,
    otp_mandatory: settings.otp_mandatory,
    name: user.name,
    external: user.external,
    login_provider: provider,
    impersonate: impersonate !== undefined,
    groups: user.groups,
    roles: user.roles,
    impersonate_user_id: impersonate !== undefined ? origin.id : null,
    capabilities: user.capabilities.map((c) => ({ id: c.id, internal_id: c.internal_id, name: c.name })),
    default_hidden_types: user.default_hidden_types,
    group_ids: user.groups?.map((g) => g.internal_id) ?? [],
    organizations: user.organizations ?? [],
    allowed_organizations: user.allowed_organizations,
    inside_platform_organization: user.inside_platform_organization,
    allowed_marking: user.allowed_marking.map((m) => ({
      id: m.id,
      standard_id: m.standard_id,
      internal_id: m.internal_id,
      definition_type: m.definition_type,
    })),
    default_marking: user.default_marking?.map((entry) => ({
      entity_type: entry.entity_type,
      values: entry.values?.map((m) => ({
        id: m.id,
        standard_id: m.standard_id,
        internal_id: m.internal_id,
        definition_type: m.definition_type,
      }))
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
export const buildCompleteUser = async (context, client) => {
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
  const [individuals, organizations, groups] = await Promise.all([individualsPromise, organizationsPromise, userGroupsPromise]);
  const roles = await getRoles(context, groups);
  const capabilitiesPromise = getCapabilities(context, client.id, roles, isUserPlatform);
  const defaultHiddenTypesPromise = getDefaultHiddenTypes(context, client.id, roles);
  const [capabilities, default_hidden_types] = await Promise.all([capabilitiesPromise, defaultHiddenTypesPromise]);
  const marking = await getUserAndGlobalMarkings(context, client.id, groups, capabilities);
  const individualId = individuals.length > 0 ? R.head(individuals).id : undefined;
  return {
    ...client,
    roles,
    capabilities,
    default_hidden_types,
    groups,
    organizations,
    allowed_organizations,
    individual_id: individualId,
    inside_platform_organization: isUserPlatform,
    allowed_marking: marking.user,
    all_marking: marking.all,
    default_marking: marking.default,
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

export const internalAuthenticateUser = async (context, req, user, provider, token, isSessionRefresh = false) => {
  let impersonate;
  const logged = await buildCompleteUser(context, user);
  const applicantId = req.headers['opencti-applicant-id'];
  if (isNotEmptyField(applicantId) && logged.id !== applicantId) {
    if (isBypassUser(logged)) {
      const applicantUser = await resolveUserById(context, applicantId);
      if (isEmptyField(applicantUser)) {
        logApp.warn(`User ${applicantId} cant be impersonate (not exists)`);
      } else {
        impersonate = applicantUser;
      }
    }
  }
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const sessionUser = buildSessionUser(logged, impersonate, provider, settings);
  const userOrigin = userWithOrigin(req, sessionUser);
  if (!isSessionRefresh) {
    await publishUserAction({
      user: userOrigin,
      event_type: 'authentication',
      event_access: 'administration',
      event_scope: 'login',
      context_data: { provider }
    });
  }
  const hasSetAccessCapability = isUserHasCapability(logged, SETTINGS_SET_ACCESSES);
  if (!hasSetAccessCapability && settings.platform_organization && logged.organizations.length === 0) {
    throw AuthenticationFailure('You can\'t login without an organization');
  }
  req.session.user = sessionUser;
  req.session.session_provider = { provider, token };
  req.session.session_refresh = false;
  req.session.save();
  return userOrigin;
};

export const authenticateUser = async (context, req, user, provider, token = '') => {
  // Build the user session with only required fields
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
        await logout(context, auth, req, res, true);
        return await authenticateUserFromRequest(context, req, res);
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
        await logout(context, auth, req, res, true);
        return await authenticateUserFromRequest(context, req, res);
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
      await logout(context, auth, req, res, true);
      return await authenticateUserFromRequest(context, req, res);
    }
    // If session is marked for refresh, reload the user data in the session
    // If session is old by a past application version, make a refresh
    if (auth.session_version !== PLATFORM_VERSION || req.session.session_refresh) {
      const { session_provider } = req.session;
      const { provider: userProvider, token: userToken } = session_provider;
      return await internalAuthenticateUser(context, req, auth, userProvider, userToken, true);
    }
    // If everything ok, return the authenticated user.
    return userWithOrigin(req, auth);
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
    } catch (err) {
      logApp.error('[OPENCTI] Authentication error', { error: err });
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
    await userSessionRefresh(OPENCTI_ADMIN_UUID);
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
