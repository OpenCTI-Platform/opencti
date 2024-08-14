import bcrypt from 'bcryptjs';
import { authenticator } from 'otplib';
import * as R from 'ramda';
import { uniq } from 'ramda';
import { v4 as uuid } from 'uuid';
import {
  ACCOUNT_STATUS_ACTIVE,
  ACCOUNT_STATUS_EXPIRED,
  ACCOUNT_STATUSES,
  BUS_TOPICS,
  DEFAULT_ACCOUNT_STATUS,
  ENABLED_DEMO_MODE,
  logApp,
  OPENCTI_SESSION,
  PLATFORM_VERSION,
} from '../config/conf';
import { AuthenticationFailure, DatabaseError, ForbiddenAccess, FunctionalError, UnsupportedError } from '../config/errors';
import { getEntitiesListFromCache, getEntitiesMapFromCache, getEntityFromCache, resetCacheForEntity } from '../database/cache';
import { elLoadBy, elRawDeleteByQuery } from '../database/engine';
import { createEntity, createRelation, deleteElementById, deleteRelationsByFromAndTo, patchAttribute, updateAttribute, updatedInputsToData } from '../database/middleware';
import {
  internalFindByIds,
  internalLoadById,
  listAllEntities,
  listAllEntitiesForFilter,
  listAllFromEntitiesThroughRelations,
  listAllRelations,
  listAllToEntitiesThroughRelations,
  listEntities,
  listEntitiesThroughRelationsPaginated,
  storeLoadById,
} from '../database/middleware-loader';
import { delEditContext, delUserContext, notify, setEditContext } from '../database/redis';
import { findSessionsForUsers, killUserSessions, markSessionForRefresh } from '../database/session';
import { buildPagination, isEmptyField, isNotEmptyField, READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { publishUserAction } from '../listener/UserActionListener';
import { ABSTRACT_INTERNAL_RELATIONSHIP, ABSTRACT_STIX_DOMAIN_OBJECT, OPENCTI_ADMIN_UUID } from '../schema/general';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../schema/internalObject';
import {
  isInternalRelationship,
  RELATION_ACCESSES_TO,
  RELATION_HAS_CAPABILITY,
  RELATION_HAS_ROLE,
  RELATION_MEMBER_OF,
  RELATION_PARTICIPATE_TO
} from '../schema/internalRelationship';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import {
  BYPASS,
  executionContext,
  INTERNAL_USERS,
  isBypassUser,
  isUserHasCapability,
  REDACTED_USER,
  SETTINGS_SET_ACCESSES,
  SYSTEM_USER,
  VIRTUAL_ORGANIZATION_ADMIN,
} from '../utils/access';
import { ASSIGNEE_FILTER, CREATOR_FILTER, PARTICIPANT_FILTER } from '../utils/filtering/filtering-constants';
import { now, utcDate } from '../utils/format';
import { addGroup } from './grant';
import { defaultMarkingDefinitionsFromGroups, findAll as findGroups } from './group';
import { addIndividual } from './individual';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { extractFilterKeys } from '../utils/filtering/filtering-utils';
import { testFilterGroup, testStringFilter } from '../utils/filtering/boolean-logic-engine';
import { computeUserEffectiveConfidenceLevel } from '../utils/confidence-level';
import { STATIC_NOTIFIER_EMAIL, STATIC_NOTIFIER_UI } from '../modules/notifier/notifier-statics';
import { cleanMarkings } from '../utils/markingDefinition-utils';

const BEARER = 'Bearer ';
const BASIC = 'Basic ';
const AUTH_BEARER = 'Bearer';
const AUTH_BASIC = 'BasicAuth';
export const TAXIIAPI = 'TAXIIAPI';
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

export const usersSessionRefresh = async (userIds) => {
  const sessions = await findSessionsForUsers(userIds);
  await Promise.all(sessions.map((s) => markSessionForRefresh(s.id)));
};

export const userSessionRefresh = async (userId) => {
  return usersSessionRefresh([userId]);
};

export const userWithOrigin = (req, user) => {
  // /!\ This metadata information is used in different ways
  // - In audit logs to identify the user
  // - In stream message to also identifier the user
  // - In logging system to know the level of the error message
  const headers_metadata = R.mergeAll((user.headers_audit ?? [])
    .map((header) => ({ [header]: req.header(header) })));
  const origin = {
    socket: 'query',
    ip: req?.ip,
    user_id: user.id,
    group_ids: user.group_ids,
    organization_ids: user.organizations?.map((o) => o.internal_id) ?? [],
    user_metadata: { ...headers_metadata },
    referer: req?.headers.referer,
    applicant_id: req?.headers['opencti-applicant-id'],
    call_retry_number: req?.headers['opencti-retry-number'],
    playbook_id: req?.headers['opencti-playbook-id']
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
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES) && user.id !== userId) {
    // if no organization in common with the logged user
    const memberOrganizations = await listAllToEntitiesThroughRelations(context, user, userId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    const myOrganizationsIds = user.administrated_organizations.map((organization) => organization.id);
    if (!memberOrganizations.map((organization) => organization.id).find((orgaId) => myOrganizationsIds.includes(orgaId))) {
      throw ForbiddenAccess();
    }
  }
  if (INTERNAL_USERS[userId]) {
    return INTERNAL_USERS[userId];
  }
  const data = await storeLoadById(context, user, userId, ENTITY_TYPE_USER);
  const withoutPassword = data ? R.dissoc('password', data) : data;
  return buildCompleteUser(context, withoutPassword);
};

export const findAll = async (context, user, args) => {
  // if user is orga_admin && not set_accesses
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    // TODO JRI REPLACE BY listEntities with filter?????
    const organisationIds = user.administrated_organizations.map((organization) => organization.id);
    const users = (await listAllFromEntitiesThroughRelations(
      context,
      user,
      organisationIds,
      RELATION_PARTICIPATE_TO,
      ENTITY_TYPE_USER,
    )).map((n) => ({ node: n }));
    return buildPagination(0, null, users, users.length);
  }
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

// build only a creator object with what we need to expose of users
const buildCreatorUser = (user) => {
  if (!user) {
    return user;
  }
  return {
    id: user.id,
    entity_type: user.entity_type,
    name: user.name,
    description: user.description,
    standard_id: user.id
  };
};
export const batchCreator = async (context, user, userIds) => {
  const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  return userIds.map((id) => INTERNAL_USERS[id] || buildCreatorUser(platformUsers.get(id)) || SYSTEM_USER);
};

export const batchCreators = async (context, user, userListIds) => {
  const userIds = userListIds.map((u) => (Array.isArray(u) ? u : [u]));
  const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  return userIds.map((ids) => ids.map((id) => INTERNAL_USERS[id] || buildCreatorUser(platformUsers.get(id)) || SYSTEM_USER));
};

export const userOrganizationsPaginated = async (context, user, userId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, userId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION, false, opts);
};

export const userGroupsPaginated = async (context, user, userId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, userId, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP, false, opts);
};

export const groupRolesPaginated = async (context, user, groupId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, groupId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, false, opts);
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

export const computeAvailableMarkings = (userMarkings, allMarkings) => {
  const computedMarkings = [];
  for (let index = 0; index < userMarkings.length; index += 1) {
    const userMarking = userMarkings[index];
    // Find all marking of same type with rank <=
    const findMarking = R.find((m) => m.id === userMarking.id, allMarkings);
    if (isNotEmptyField(findMarking)) {
      // Add the marking in the list
      computedMarkings.push(findMarking);
      // Compute accessible lower markings
      const { x_opencti_order: order, definition_type: type } = findMarking;
      const lowerMatchingMarkings = R.filter((m) => {
        return userMarking.id !== m.id && m.definition_type === type && m.x_opencti_order <= order;
      }, allMarkings);
      computedMarkings.push(...lowerMatchingMarkings);
    } else {
      const error = { marking: userMarking, available_markings: allMarkings };
      throw UnsupportedError('[ACCESS] USER MARKING INACCESSIBLE', { error });
    }
  }
  return R.uniqBy((m) => m.id, computedMarkings);
};

// Return all the available markings a user can share
export const getAvailableDataSharingMarkings = async (context, user) => {
  const maxMarkings = user.max_shareable_marking;
  const allMarkings = await getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  return computeAvailableMarkings(maxMarkings, allMarkings);
};

export const checkUserCanShareMarkings = async (context, user, markingsToShare) => {
  const shareableMarkings = await getAvailableDataSharingMarkings(context, user);
  const contentMaxMarkingsIsShareable = markingsToShare.every((m) => (
    shareableMarkings.some((shareableMarking) => m.definition_type === shareableMarking.definition_type && m.x_opencti_order <= shareableMarking.x_opencti_order)));
  if (!contentMaxMarkingsIsShareable) {
    throw new Error('You are not allowed to share these markings.');
  }
};

const getUserAndGlobalMarkings = async (context, userId, userGroups, capabilities) => {
  const groupIds = userGroups.map((r) => r.id);
  const userCapabilities = capabilities.map((c) => c.name);
  const shouldBypass = userCapabilities.includes(BYPASS) || userId === OPENCTI_ADMIN_UUID;
  const allMarkingsPromise = getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const defaultGroupMarkingsPromise = defaultMarkingDefinitionsFromGroups(context, groupIds);
  let userMarkings;
  let maxShareableMarkings;
  const [all, defaultMarkings] = await Promise.all([allMarkingsPromise, defaultGroupMarkingsPromise]);

  if (shouldBypass) { // Bypass user have all platform markings and can share all markings
    userMarkings = all;
    maxShareableMarkings = all;
  } else { // Standard user have markings related to his groups
    userMarkings = await listAllToEntitiesThroughRelations(context, SYSTEM_USER, groupIds, RELATION_ACCESSES_TO, ENTITY_TYPE_MARKING_DEFINITION);

    const notShareableMarkings = userGroups.flatMap(
      ({ max_shareable_markings }) => max_shareable_markings?.filter(({ value }) => value === 'none')
        .map(({ type }) => type)
    );

    maxShareableMarkings = userGroups.flatMap(({ max_shareable_markings }) => max_shareable_markings?.filter(({ value }) => value !== 'none')).filter((m) => !!m);

    const allShareableMarkings = all.filter(({ definition_type }) => (
      !notShareableMarkings.includes(definition_type) && !maxShareableMarkings.some(({ type }) => type === definition_type)
    )).filter(({ id }) => userMarkings.some((m) => m.id === id)).map(({ id }) => id);
    maxShareableMarkings = [...maxShareableMarkings.map(({ value }) => value), ...allShareableMarkings];
  }

  const computedMarkings = computeAvailableMarkings(userMarkings, all);
  return { user: computedMarkings, all, default: defaultMarkings, max_shareable: await cleanMarkings(context, maxShareableMarkings) };
};

export const getRoles = async (context, userGroups) => {
  const groupIds = userGroups.map((r) => r.id);
  return listAllToEntitiesThroughRelations(context, SYSTEM_USER, groupIds, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE);
};

export const getCapabilities = async (context, userId, userRoles) => {
  const roleIds = userRoles.map((r) => r.id);
  const capabilities = await listAllToEntitiesThroughRelations(context, SYSTEM_USER, roleIds, RELATION_HAS_CAPABILITY, ENTITY_TYPE_CAPABILITY);
  // Force push the bypass for default admin
  const withoutBypass = !capabilities.some((c) => c.name === BYPASS);
  if (userId === OPENCTI_ADMIN_UUID && withoutBypass) {
    const id = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: BYPASS });
    capabilities.push({ id, standard_id: id, internal_id: id, name: BYPASS });
    return capabilities;
  }
  return capabilities;
};

export const roleCapabilities = async (context, user, roleId) => {
  return listAllToEntitiesThroughRelations(context, user, roleId, RELATION_HAS_CAPABILITY, ENTITY_TYPE_CAPABILITY);
};

export const getDefaultHiddenTypes = (entities) => {
  let userDefaultHiddenTypes = entities.map((entity) => entity.default_hidden_types).flat();
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
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES) && isUserHasCapability(user, VIRTUAL_ORGANIZATION_ADMIN)) {
    throw ForbiddenAccess();
  }
  const targetUser = await findById(context, user, userId);
  if (!targetUser) {
    throw FunctionalError('Cannot add the relation, User cannot be found.');
  }

  const input = { fromId: userId, toId: organizationId, relationship_type: RELATION_PARTICIPATE_TO };
  const created = await createRelation(context, user, input);
  const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : created.from.user_email;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds ${created.toType} \`${extractEntityRepresentativeName(created.to)}\` to user \`${actionEmail}\``,
    context_data: { id: userId, entity_type: ENTITY_TYPE_USER, input }
  });

  await userSessionRefresh(userId);
  resetCacheForEntity(ENTITY_TYPE_SETTINGS);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, targetUser, user);
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

export const addUser = async (context, user, newUser) => {
  const userEmail = newUser.user_email.toLowerCase();
  const existingUser = await elLoadBy(context, SYSTEM_USER, 'user_email', userEmail, ENTITY_TYPE_USER);
  if (existingUser) {
    throw FunctionalError('User already exists', { user_id: existingUser.internal_id });
  }
  if (isUserHasCapability(user, VIRTUAL_ORGANIZATION_ADMIN) && !isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    // user is Organization Admin
    // Check organization
    const myOrganizationIds = user.administrated_organizations.map((organization) => organization.id);
    if (newUser.objectOrganization.length === 0 || !newUser.objectOrganization.every((orga) => myOrganizationIds.includes(orga))) {
      throw ForbiddenAccess();
    }
    const myGroupIds = R.uniq(user.administrated_organizations.map((orga) => orga.grantable_groups).flat());
    if (!newUser.groups.every((group) => myGroupIds.includes(group))) {
      throw ForbiddenAccess();
    }
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
    R.assoc('account_status', newUser.account_status ? newUser.account_status : DEFAULT_ACCOUNT_STATUS),
    R.assoc('account_lock_after_date', newUser.account_lock_after_date),
    R.assoc('unit_system', newUser.unit_system),
    R.assoc('user_confidence_level', newUser.user_confidence_level ?? null), // can be null
    R.assoc('personal_notifiers', [STATIC_NOTIFIER_UI, STATIC_NOTIFIER_EMAIL]),
    R.dissoc('roles'),
    R.dissoc('groups')
  )(newUser);
  const { element, isCreation } = await createEntity(context, user, userToCreate, ENTITY_TYPE_USER, { complete: true });
  // Link to organizations
  const userOrganizations = newUser.objectOrganization ?? [];
  const relationOrganizations = userOrganizations.map((organizationId) => ({
    fromId: element.id,
    toId: organizationId,
    relationship_type: RELATION_PARTICIPATE_TO,
  }));
  await Promise.all(relationOrganizations.map((relation) => createRelation(context, user, relation)));
  // Either use the provided groups or Assign the default groups to user (SSO)
  const userRelationGroups = (newUser.groups ?? []).map((group) => ({
    fromId: element.id,
    toId: group,
    relationship_type: RELATION_MEMBER_OF,
  }));
  const defaultAssignationFilter = {
    mode: 'and',
    filters: [{ key: 'default_assignation', values: [true] }],
    filterGroups: [],
  };
  const defaultGroups = await findGroups(context, user, { filters: defaultAssignationFilter });
  const defaultRelationGroups = defaultGroups.edges.map((e) => ({
    fromId: element.id,
    toId: e.node.internal_id,
    relationship_type: RELATION_MEMBER_OF,
  }));
  const relationGroups = [...userRelationGroups, ...defaultRelationGroups];
  await Promise.all(relationGroups.map((relation) => createRelation(context, user, relation)));
  // Audit log
  if (isCreation) {
    const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : newUser.user_email;
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates user \`${actionEmail}\``,
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
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method, got ${input.relationship_type}.`);
  }
  const finalInput = R.assoc('fromId', roleId, input);
  const relationData = await createRelation(context, user, finalInput);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds ${relationData.to.entity_type} \`${extractEntityRepresentativeName(relationData.to)}\` for role \`${role.name}\``,
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
    message: `removes ${deleted.to.entity_type} \`${extractEntityRepresentativeName(deleted.to)}\` for role \`${role.name}\``,
    context_data: { id: roleId, entity_type: ENTITY_TYPE_ROLE, input }
  });
  await roleSessionRefresh(context, user, roleId);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user);
};

// User related
export const userEditField = async (context, user, userId, rawInputs) => {
  const inputs = [];
  const userToUpdate = await internalLoadById(context, user, userId);
  // Check in an organization admin edits a user that's not in its administrated organizations
  const myAdministratedOrganizationsIds = user.administrated_organizations.map((orga) => orga.id);
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES) && isUserHasCapability(user, VIRTUAL_ORGANIZATION_ADMIN)) {
    if (userId !== user.id && !userToUpdate[RELATION_PARTICIPATE_TO].find((orga) => myAdministratedOrganizationsIds.includes(orga))) {
      throw ForbiddenAccess();
    }
  }
  for (let index = 0; index < rawInputs.length; index += 1) {
    const input = rawInputs[index];
    if (input.key === 'password') {
      const userPassword = R.head(input.value).toString();
      await checkPasswordFromPolicy(context, userPassword);
      input.value = [bcrypt.hashSync(userPassword)];
    }
    if (input.key === 'account_status') {
      // If account status is not active, kill all current user sessions
      if (R.head(input.value) !== ACCOUNT_STATUS_ACTIVE) {
        await killUserSessions(userId);
      }
      // If moving to unexpired status and expiration date is already in the past, reset the value
      if (R.head(input.value) !== ACCOUNT_STATUS_EXPIRED && userToUpdate.account_lock_after_date
        && utcDate().isAfter(userToUpdate.account_lock_after_date)) {
        inputs.push({ key: 'account_lock_after_date', value: [null] });
      }
    }
    if (input.key === 'account_lock_after_date' && utcDate().isAfter(utcDate(R.head(input.value)))) {
      inputs.push({ key: 'account_status', value: [ACCOUNT_STATUS_EXPIRED] });
      await killUserSessions(userId);
    }
    if (input.key === 'user_confidence_level') {
      // user's effective level might have changed, we need to refresh session info
      await userSessionRefresh(userId);
    }
    inputs.push(input);
  }
  const { element } = await updateAttribute(context, user, userId, ENTITY_TYPE_USER, inputs);
  const input = updatedInputsToData(element, inputs);
  const personalUpdate = user.id === userId;
  const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : element.user_email;
  const userAction = {
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: personalUpdate ? 'extended' : 'administration',
    message: `updates \`${inputs.map((i) => i.key).join(', ')}\` for ${personalUpdate ? '`themselves`' : `user \`${actionEmail}\``}`,
    context_data: { id: userId, entity_type: ENTITY_TYPE_USER, input }
  };
  await publishUserAction(userAction);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, element, user);
};

export const deleteBookmark = async (context, user, id) => {
  const currentUser = await storeLoadById(context, user, user.id, ENTITY_TYPE_USER);
  const currentBookmarks = currentUser.bookmarks ? currentUser.bookmarks : [];
  const newBookmarks = R.filter((n) => n.id !== id, currentBookmarks);
  await patchAttribute(context, user, user.id, ENTITY_TYPE_USER, { bookmarks: newBookmarks });
  return id;
};

export const bookmarks = async (context, user, args) => {
  const { types = [], filters = null } = args;
  const currentUser = await storeLoadById(context, user, user.id, ENTITY_TYPE_USER);
  // handle types
  let bookmarkList = types && types.length > 0
    ? (currentUser.bookmarks ?? []).filter((n) => types.includes(n.type))
    : currentUser.bookmarks || [];
  // handle filters
  if (filters) {
    // check filters are supported
    // i.e. filters can only contains filters with key=entity_type
    if (extractFilterKeys(filters).filter((f) => f !== 'entity_type').length > 0) {
      throw UnsupportedError('Bookmarks widgets only support filter with key=entity_type.');
    }
    // filter the bookmark list according to the filters
    const entityTypeBookmarkTester = {
      entity_type: (data, filter) => {
        const values = [data.type]; // data is a bookmark
        return testStringFilter(filter, values);
      }
    };
    bookmarkList = bookmarkList.filter((mark) => testFilterGroup(mark, filters, entityTypeBookmarkTester));
  }
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

export const isUserTheLastAdmin = (userId, authorized_members) => {
  if (authorized_members !== null && authorized_members !== undefined) {
    const currentUserIsAdmin = authorized_members.some(({ id, access_right }) => id === userId && access_right === 'admin');
    const anotherUserIsAdmin = authorized_members.some(({ id, access_right }) => id !== userId && access_right === 'admin');

    return currentUserIsAdmin && !anotherUserIsAdmin;
  }
  // if for some reason there is no authorized_member, then nothing prevent from deleting.
  return false;
};

export const deleteAllWorkspaceForUser = async (context, authUser, userId) => {
  const userToDeleteAuth = await findById(context, authUser, userId);

  const workspacesToDelete = await listAllEntities(context, userToDeleteAuth, [ENTITY_TYPE_WORKSPACE], { connectionFormat: false });

  const workspaceToDeleteIds = workspacesToDelete
    .filter((workspaceEntity) => isUserTheLastAdmin(userId, workspaceEntity.authorized_members))
    .map((workspaceEntity) => workspaceEntity.internal_id);

  if (workspaceToDeleteIds.length > 0) {
    await elRawDeleteByQuery({
      index: READ_INDEX_INTERNAL_OBJECTS,
      refresh: true,
      body: {
        query: {
          bool: {
            must: [
              { term: { 'entity_type.keyword': { value: 'Workspace' } } },
              { terms: { 'internal_id.keyword': workspaceToDeleteIds } }
            ]
          }
        }
      }
    }).catch((err) => {
      throw DatabaseError('[DELETE] Error deleting Workspace for user ', { cause: err, user_id: userId });
    });
  }
  return true;
};

export const deleteAllTriggerAndDigestByUser = async (userId) => {
  return await elRawDeleteByQuery({
    index: READ_INDEX_INTERNAL_OBJECTS,
    refresh: true,
    body: {
      query: {
        bool: {
          must: [
            { term: { 'entity_type.keyword': { value: 'Trigger' } } },
            { term: { 'authorized_members.id.keyword': { value: userId } } }
          ]
        }
      }
    }
  }).catch((err) => {
    throw DatabaseError('[DELETE] Error deleting Trigger for user', { cause: err, user_id: userId });
  });
};
export const deleteAllNotificationByUser = async (userId) => {
  return await elRawDeleteByQuery({
    index: READ_INDEX_INTERNAL_OBJECTS,
    refresh: true,
    body: {
      query: {
        bool: {
          must: [
            { term: { 'entity_type.keyword': { value: 'Notification' } } },
            { term: { 'user_id.keyword': { value: userId } } }
          ]
        }
      }
    }
  }).catch((err) => {
    throw DatabaseError('[DELETE] Error deleting notification for user', { cause: err, user_id: userId });
  });
};

/**
 * Delete a user and related data:
 * - Delete relation
 * - Delete user's Notification, Digests and Triggers (both are Triggers)
 * - Delete user's Investigation and Dashboard (both are Workspace) that are not shared to another 'admin'.
 *
 * User workspace where the user is 'admin' and having other users are deleted too.
 * Only one audit log is create for the user deletion. No audit log for Notification, Triggers, Workspace deletion.
 * @param context
 * @param user the user that is user to call delete
 * @param userId id of user to delete and cleanup data
 * @returns {Promise<*>}
 */
export const userDelete = async (context, user, userId) => {
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES) && isUserHasCapability(user, VIRTUAL_ORGANIZATION_ADMIN)) {
    // When user is organization admin, we make sure that the deleted user is in one of the administrated organizations of the admin
    const userData = await storeLoadById(context, user, userId, ENTITY_TYPE_USER);
    const myAdministratedOrganizationsIds = user.administrated_organizations.map(({ id }) => id);
    if (!userData['rel_granted.internal_id'].find((orga) => myAdministratedOrganizationsIds.includes(orga))) {
      throw ForbiddenAccess();
    }
  }
  await deleteAllTriggerAndDigestByUser(userId);
  await deleteAllNotificationByUser(userId);
  await deleteAllWorkspaceForUser(context, user, userId);

  const deleted = await deleteElementById(context, user, userId, ENTITY_TYPE_USER);
  const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : deleted.user_email;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes user \`${actionEmail}\``,
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
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method, got ${input.relationship_type}.`);
  }
  // Check in case organization admins adds non-grantable goup a user
  const myGrantableGroups = R.uniq(user.administrated_organizations.map((orga) => orga.grantable_groups).flat());
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES) && isUserHasCapability(user, VIRTUAL_ORGANIZATION_ADMIN)) {
    if (input.relationship_type === 'member-of' && !myGrantableGroups.includes(input.toId)) {
      throw ForbiddenAccess();
    }
  }
  const finalInput = R.assoc('fromId', userId, input);
  const relationData = await createRelation(context, user, finalInput);
  const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : userData.user_email;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds ${relationData.toType} \`${extractEntityRepresentativeName(relationData.to)}\` for user \`${actionEmail}\``,
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
  const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : targetUser.user_email;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `removes ${to.entity_type} \`${extractEntityRepresentativeName(to)}\` for user \`${actionEmail}\``,
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
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES) && isUserHasCapability(user, VIRTUAL_ORGANIZATION_ADMIN)) {
    throw ForbiddenAccess();
  }
  const targetUser = await findById(context, user, userId);
  if (!targetUser) {
    throw FunctionalError('Cannot delete the relation, User cannot be found.');
  }

  const { to } = await deleteRelationsByFromAndTo(context, user, userId, toId, RELATION_PARTICIPATE_TO, ABSTRACT_INTERNAL_RELATIONSHIP);
  if (to.authorized_authorities?.includes(userId)) {
    const indexOfMember = to.authorized_authorities.indexOf(userId);
    to.authorized_authorities.splice(indexOfMember, 1);
    const patch = { authorized_authorities: to.authorized_authorities };
    const { element } = await patchAttribute(context, user, toId, ENTITY_TYPE_IDENTITY_ORGANIZATION, patch);
    await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, element, user);
  }

  const input = { relationship_type: RELATION_PARTICIPATE_TO, toId };
  const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : targetUser.user_email;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `removes ${to.entity_type} \`${extractEntityRepresentativeName(to)}\` for user \`${actionEmail}\``,
    context_data: { id: userId, entity_type: ENTITY_TYPE_USER, input }
  });
  await userSessionRefresh(userId);
  resetCacheForEntity(ENTITY_TYPE_SETTINGS);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, targetUser, user);
};

export const loginFromProvider = async (userInfo, opts = {}) => {
  const { providerGroups = [], providerOrganizations = [], autoCreateGroup = false } = opts;
  const context = executionContext('login_provider');
  // region test the groups existence and eventually auto create groups
  if (providerGroups.length > 0) {
    const providerGroupsIds = providerGroups.map((groupName) => generateStandardId(ENTITY_TYPE_GROUP, { name: groupName }));
    const groupsFilters = {
      mode: 'and',
      filters: [{ key: 'standard_id', values: providerGroupsIds }],
      filterGroups: [],
    };
    const foundGroups = await findGroups(context, SYSTEM_USER, { filters: groupsFilters });
    const foundGroupsNames = foundGroups.edges.map((group) => group.node.name);
    const newGroupsToCreate = [];
    providerGroups.forEach((groupName) => {
      if (!foundGroupsNames.includes(groupName)) {
        if (!autoCreateGroup) {
          throw ForbiddenAccess('[SSO] Can\'t login. The user has groups that don\'t exist and auto_create_group = false.');
        } else {
          newGroupsToCreate.push(addGroup(context, SYSTEM_USER, { name: groupName }));
        }
      }
    });
    await Promise.all(newGroupsToCreate);
  }
  // endregion
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const { email, name: providedName, firstname, lastname } = userInfo;
  if (isEmptyField(email)) {
    throw ForbiddenAccess('User email not provided');
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
    const userGroups = await listAllToEntitiesThroughRelations(context, SYSTEM_USER, user.id, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP);
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
    const userOrganizations = await listAllToEntitiesThroughRelations(context, SYSTEM_USER, user.id, RELATION_PARTICIPATE_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION);
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
  return { ...user, provider_metadata: userInfo.provider_metadata };
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
  // User activation can only be done if otp is not already activated
  if (user.otp_activated) {
    throw UnsupportedError('You need to deactivate your current 2FA before generating a new one');
  }
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

const regenerateUserSession = async (user, req, res) => {
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
    account_status: user.account_status,
    account_lock_after_date: user.account_lock_after_date,
    unit_system: user.unit_system,
    submenu_show_icons: user.submenu_show_icons,
    submenu_auto_collapse: user.submenu_auto_collapse,
    monochrome_labels: user.monochrome_labels,
    groups: user.groups,
    roles: user.roles,
    impersonate: impersonate !== undefined,
    impersonate_user_id: impersonate !== undefined ? origin.id : null,
    capabilities: user.capabilities.map((c) => ({ id: c.id, internal_id: c.internal_id, name: c.name })),
    default_hidden_types: user.default_hidden_types,
    group_ids: user.groups?.map((g) => g.internal_id) ?? [],
    organizations: user.organizations ?? [],
    allowed_organizations: user.allowed_organizations,
    administrated_organizations: user.administrated_organizations ?? [],
    inside_platform_organization: user.inside_platform_organization,
    allowed_marking: user.allowed_marking.map((m) => ({
      id: m.id,
      standard_id: m.standard_id,
      internal_id: m.internal_id,
      definition_type: m.definition_type,
    })),
    max_shareable_marking: user.max_shareable_marking.map((m) => ({
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
    session_version: PLATFORM_VERSION,
    effective_confidence_level: user.effective_confidence_level,
    no_creators: user.no_creators,
    restrict_delete: user.restrict_delete,
    personal_notifiers: user.personal_notifiers,
    ...user.provider_metadata
  };
};

const virtualOrganizationAdminCapability = {
  id: uuid(),
  standard_id: `capability--${uuid()}`,
  name: VIRTUAL_ORGANIZATION_ADMIN,
  entity_type: 'Capability',
  parent_types: ['Basic-Object', 'Internal-Object'],
  created_at: Date.now(),
  updated_at: Date.now()
};
const getStackTrace = () => {
  const obj = {};
  Error.captureStackTrace(obj, getStackTrace);
  return obj.stack;
};
export const buildCompleteUser = async (context, client) => {
  if (!client) {
    return undefined;
  }
  const initialCallStack = getStackTrace();
  logApp.debug('Building complete user', { client, stack: initialCallStack });
  const contactInformationFilter = {
    mode: 'and',
    filters: [{ key: 'contact_information', values: [client.user_email] }],
    filterGroups: [],
  };
  // find user corresponding individual (we need only to get the first one)
  const individualArgs = { first: 1, indices: [READ_INDEX_STIX_DOMAIN_OBJECTS], filters: contactInformationFilter, connectionFormat: false, noFiltersChecking: true };
  const individualsPromise = listEntities(context, SYSTEM_USER, [ENTITY_TYPE_IDENTITY_INDIVIDUAL], individualArgs);
  const organizationsPromise = listAllToEntitiesThroughRelations(
    context,
    SYSTEM_USER,
    client.id,
    RELATION_PARTICIPATE_TO,
    ENTITY_TYPE_IDENTITY_ORGANIZATION,
    { withInferences: true }
  );
  const userGroupsPromise = listAllToEntitiesThroughRelations(context, SYSTEM_USER, client.id, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP);
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const allowed_organizations = await listAllToEntitiesThroughRelations(context, SYSTEM_USER, client.id, RELATION_PARTICIPATE_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  const userOrganizations = allowed_organizations.map((m) => m.internal_id);
  const isUserPlatform = settings.platform_organization ? userOrganizations.includes(settings.platform_organization) : true;
  const [individuals, organizations, groups] = await Promise.all([individualsPromise, organizationsPromise, userGroupsPromise]);
  const roles = await getRoles(context, groups);
  const capabilities = await getCapabilities(context, client.id, roles);
  const isByPass = R.find((s) => s.name === BYPASS, capabilities) !== undefined;
  const marking = await getUserAndGlobalMarkings(context, client.id, groups, capabilities);
  const administrated_organizations = organizations.filter((o) => o.authorized_authorities?.includes(client.id));
  if (administrated_organizations.length > 0) {
    capabilities.push(virtualOrganizationAdminCapability);
  }
  const individualId = individuals.length > 0 ? R.head(individuals).id : undefined;

  // Default hidden types
  const defaultHiddenTypesGroups = getDefaultHiddenTypes(groups);
  const defaultHiddenTypesOrgs = getDefaultHiddenTypes(allowed_organizations);
  const default_hidden_types = uniq(defaultHiddenTypesGroups.concat(defaultHiddenTypesOrgs));

  // effective confidence level
  const effective_confidence_level = computeUserEffectiveConfidenceLevel({ ...client, groups, capabilities });

  // Other groups attribute
  const no_creators = groups.filter((g) => g.no_creators).length === groups.length;
  const restrict_delete = !isByPass && groups.filter((g) => g.restrict_delete).length === groups.length;

  return {
    ...client,
    roles,
    capabilities,
    default_hidden_types,
    groups,
    organizations,
    allowed_organizations,
    administrated_organizations,
    individual_id: individualId,
    inside_platform_organization: isUserPlatform,
    allowed_marking: marking.user,
    all_marking: marking.all,
    default_marking: marking.default,
    max_shareable_marking: marking.max_shareable,
    effective_confidence_level,
    no_creators,
    restrict_delete,
  };
};

export const resolveUserByIdFromCache = async (context, id) => {
  if (INTERNAL_USERS[id]) return INTERNAL_USERS[id];
  const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  return platformUsers.get(id);
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

/**
 * Validates a user before granting authorization.
 *
 * @param {AuthUser} user
 * @param {Object} settings
 * @throws {AuthenticationFailure} if the user has an invalid account status.
 */
const validateUser = (user, settings) => {
  // Check organization consistency
  const hasSetAccessCapability = isUserHasCapability(user, SETTINGS_SET_ACCESSES);
  if (!hasSetAccessCapability && settings.platform_organization && user.organizations.length === 0) {
    throw AuthenticationFailure('You can\'t login without an organization');
  }
  // Check account expiration date
  if (user.account_lock_after_date && utcDate().isAfter(utcDate(user.account_lock_after_date))) {
    throw AuthenticationFailure(ACCOUNT_STATUSES.Expired);
  }
  // Validate user's account status
  if (user.account_status !== ACCOUNT_STATUS_ACTIVE) {
    throw AuthenticationFailure(ACCOUNT_STATUSES[user.account_status]);
  }
};

export const internalAuthenticateUser = async (context, req, user, provider, { token, previousSession, isSessionRefresh }) => {
  let impersonate;
  const logged = await buildCompleteUser(context, user);
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  validateUser(logged, settings);
  const applicantId = req.headers['opencti-applicant-id'];
  if (isNotEmptyField(applicantId) && logged.id !== applicantId) {
    if (isBypassUser(logged)) {
      const applicantUser = await resolveUserByIdFromCache(context, applicantId);
      if (isEmptyField(applicantUser)) {
        logApp.warn('User cant be impersonate (not exists)', { applicantId });
      } else {
        impersonate = applicantUser;
      }
    }
  }
  const sessionUser = buildSessionUser(logged, impersonate, provider, settings);
  // If previous session stored, some specific attributes needs to follow
  if (previousSession) {
    sessionUser.otp_validated = previousSession.otp_validated;
    sessionUser.impersonate = previousSession.impersonate;
    sessionUser.impersonate_user_id = previousSession.impersonate_user_id;
  }
  const userOrigin = userWithOrigin(req, sessionUser);
  if (isEmptyField(user.stateless_session) || user.stateless_session === false) {
    if (!isSessionRefresh) {
      await publishUserAction({
        user: userOrigin,
        event_type: 'authentication',
        event_access: 'administration',
        event_scope: 'login',
        context_data: { provider }
      });
    }
    req.session.user = sessionUser;
    req.session.session_provider = { provider, token };
    req.session.session_refresh = false;
    req.session.save();
  }
  return userOrigin;
};

export const authenticateUser = async (context, req, user, provider, opts = {}) => {
  // Build the user session with only required fields
  return internalAuthenticateUser(context, req, user, provider, opts);
};

export const HEADERS_AUTHENTICATORS = [];
export const authenticateUserFromRequest = async (context, req, res, isSessionRefresh = false) => {
  const auth = req.session?.user;
  // If user already have a session
  if (auth && !isSessionRefresh) {
    // User already identified, we need to enforce the session validity
    const { provider, token } = req.session.session_provider;
    // For bearer, validate that the bearer is the same as the session
    if (provider === AUTH_BEARER) {
      const currentToken = extractTokenFromBearer(req.headers.authorization);
      if (currentToken !== token) {
        // Session doesn't match, kill the current session and try to re auth
        await regenerateUserSession(auth, req, res);
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
        await regenerateUserSession(auth, req, res);
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
      return await authenticateUserFromRequest(context, req, res, true);
    }
    // If session is marked for refresh, reload the user data in the session
    // If session is old by a past application version, make a refresh
    if (auth.session_version !== PLATFORM_VERSION || req.session.session_refresh) {
      const refreshOpts = { token, previousSession: auth, isSessionRefresh: true };
      const user = await internalLoadById(context, SYSTEM_USER, auth.impersonate_user_id ?? auth.id);
      return await internalAuthenticateUser(context, req, user, provider, refreshOpts);
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
        const opts = { token: tokenUUID, isSessionRefresh };
        return await authenticateUser(context, req, user, loginProvider, opts);
      }
    } catch (err) {
      logApp.error(err);
    }
  }
  // If user still not identified, try headers authentication
  if (HEADERS_AUTHENTICATORS.length > 0) {
    for (let i = 0; i < HEADERS_AUTHENTICATORS.length; i += 1) {
      const headProvider = HEADERS_AUTHENTICATORS[i];
      const user = await headProvider.reqLoginHandler(req);
      if (user) {
        return await authenticateUser(context, req, user, headProvider.provider);
      }
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
      account_status: ACCOUNT_STATUS_ACTIVE,
      user_email: email,
      password: bcrypt.hashSync(password.toString()),
      api_token: tokenValue,
      external: true,
    };
    await patchAttribute(context, SYSTEM_USER, existingAdmin.id, ENTITY_TYPE_USER, patch);
  } else {
    const userToCreate = {
      internal_id: OPENCTI_ADMIN_UUID,
      external: true,
      user_email: email.toLowerCase(),
      account_status: ACCOUNT_STATUS_ACTIVE,
      name: 'admin',
      firstname: 'Admin',
      lastname: 'OpenCTI',
      description: 'Principal admin account',
      api_token: tokenValue,
      password: password.toString(),
      user_confidence_level: {
        max_confidence: 100,
        overrides: [],
      },
    };
    await addUser(context, SYSTEM_USER, userToCreate);
    await userSessionRefresh(OPENCTI_ADMIN_UUID);
  }
};

export const findDefaultDashboards = async (context, user, currentUser) => {
  const groupsDashboardIds = (currentUser.groups ?? []).map(({ default_dashboard }) => default_dashboard);
  const orgaDashboardIds = (currentUser.organizations ?? []).map(({ default_dashboard }) => default_dashboard);
  const ids = [...orgaDashboardIds, ...groupsDashboardIds].filter((id) => id);
  const dashboards = await internalFindByIds(context, user, ids, { type: ENTITY_TYPE_WORKSPACE });
  // Sort dashboards the same order as the fetched ids
  return dashboards.sort((a, b) => ids.indexOf(a.id) - ids.indexOf(b.id));
};

// region context
export const userCleanContext = async (context, user, userId) => {
  await delEditContext(user, userId);
  return storeLoadById(context, user, userId, ENTITY_TYPE_USER);
};

export const userEditContext = async (context, user, userId, input) => {
  await setEditContext(user, userId, input);
  return storeLoadById(context, user, userId, ENTITY_TYPE_USER);
};
// endregion

const buildCompleteUserFromCacheOrDb = async (context, user, userToLoad, cachedUsers) => {
  const cachedUser = cachedUsers.get(userToLoad.id);
  let completeUser;
  if (cachedUser) {
    // in case we need to resolve user effective confidence level on edit (cache not updated with user edited fields yet)
    // we need groups and capabilities to compute user effective confidence level, which are accurate in cache.
    completeUser = {
      ...userToLoad,
      groups: cachedUser.groups,
      capabilities: cachedUser.capabilities,
    };
  } else { // in case we need to resolve user effective confidence level on creation.
    completeUser = await findById(context, user, userToLoad.id);
  }
  return completeUser;
};

export const batchUserEffectiveConfidenceLevel = async (context, user, batchUsers) => {
  const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const completeUsers = [];
  for (let i = 0; i < batchUsers.length; i += 1) {
    const batchUser = batchUsers[i];
    const completeUser = await buildCompleteUserFromCacheOrDb(context, user, batchUser, platformUsers);
    completeUsers.push(completeUser);
  }
  return completeUsers.map((u) => computeUserEffectiveConfidenceLevel(u));
};

export const getUserEffectiveConfidenceLevel = async (user, context) => {
  // we load the user from cache to have the complete user with groupos
  const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const completeUser = await buildCompleteUserFromCacheOrDb(context, context.user, user, platformUsers);
  return computeUserEffectiveConfidenceLevel(completeUser);
};
