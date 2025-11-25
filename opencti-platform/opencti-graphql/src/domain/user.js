import bcrypt from 'bcryptjs';
import { authenticator } from 'otplib';
import * as R from 'ramda';
import { uniq } from 'ramda';
import { v4 as uuid } from 'uuid';
import ejs from 'ejs';
import { DateTime } from 'luxon';
import {
  ACCOUNT_STATUS_ACTIVE,
  ACCOUNT_STATUS_EXPIRED,
  ACCOUNT_STATUSES,
  BUS_TOPICS,
  DEFAULT_ACCOUNT_STATUS,
  ENABLED_DEMO_MODE,
  getRequestAuditHeaders,
  logApp
} from '../config/conf';
import { AuthenticationFailure, DatabaseError, DraftLockedError, ForbiddenAccess, FunctionalError, UnsupportedError } from '../config/errors';
import { getEntitiesListFromCache, getEntitiesMapFromCache, getEntityFromCache } from '../database/cache';
import { elLoadBy, elRawDeleteByQuery } from '../database/engine';
import { createEntity, createRelation, deleteElementById, deleteRelationsByFromAndTo, patchAttribute, updateAttribute, updatedInputsToData } from '../database/middleware';
import {
  internalFindByIds,
  internalLoadById,
  fullEntitiesList,
  fullEntitiesThoughAggregationConnection,
  fullRelationsList,
  fullEntitiesThroughRelationsToList,
  pageEntitiesConnection,
  pageRegardingEntitiesConnection,
  storeLoadById
} from '../database/middleware-loader';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { killUserSessions } from '../database/session';
import { buildPagination, isEmptyField, isNotEmptyField, READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { publishUserAction } from '../listener/UserActionListener';
import { authorizedMembers } from '../schema/attribute-definition';
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
  applyOrganizationRestriction,
  BYPASS,
  executionContext,
  FilterMembersMode,
  filterMembersWithUsersOrgs,
  INTERNAL_USERS,
  INTERNAL_USERS_WITHOUT_REDACTED,
  isBypassUser,
  isOnlyOrgaAdmin,
  isUserHasCapability,
  REDACTED_USER,
  SETTINGS_SET_ACCESSES,
  SYSTEM_USER,
  VIRTUAL_ORGANIZATION_ADMIN
} from '../utils/access';
import { ASSIGNEE_FILTER, CREATOR_FILTER, PARTICIPANT_FILTER } from '../utils/filtering/filtering-constants';
import { now, utcDate } from '../utils/format';
import { addGroup } from './grant';
import { defaultMarkingDefinitionsFromGroups, findGroupPaginated as findGroups } from './group';
import { addIndividual } from './individual';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { extractFilterKeys, isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import { testFilterGroup, testStringFilter } from '../utils/filtering/boolean-logic-engine';
import { computeUserEffectiveConfidenceLevel } from '../utils/confidence-level';
import { STATIC_NOTIFIER_EMAIL, STATIC_NOTIFIER_UI } from '../modules/notifier/notifier-statics';
import { cleanMarkings } from '../utils/markingDefinition-utils';
import { UnitSystem } from '../generated/graphql';
import { DRAFT_STATUS_OPEN } from '../modules/draftWorkspace/draftStatuses';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { addServiceAccountIntoUserCount, addUserEmailSendCount, addUserIntoServiceAccountCount } from '../manager/telemetryManager';
import { sendMail } from '../database/smtp';
import { checkEnterpriseEdition } from '../enterprise-edition/ee';
import { ENTITY_TYPE_EMAIL_TEMPLATE } from '../modules/emailTemplate/emailTemplate-types';
import { doYield } from '../utils/eventloop-utils';

const BEARER = 'Bearer ';
const BASIC = 'Basic ';
export const TAXIIAPI = 'TAXIIAPI';
const PLATFORM_ORGANIZATION = 'settings_platform_organization';
export const MEMBERS_ENTITY_TYPES = [ENTITY_TYPE_USER, ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_GROUP];
const PROTECTED_USER_ATTRIBUTES = ['api_token', 'external'];
const PROTECTED_EXTERNAL_ATTRIBUTES = ['user_email', 'user_name'];
const ME_USER_MODIFIABLE_ATTRIBUTES = [
  'user_email',
  'user_name',
  'description',
  'firstname',
  'lastname',
  'theme',
  'language',
  'personal_notifiers',
  'default_dashboard',
  'default_time_field',
  'unit_system',
  'submenu_show_icons',
  'submenu_auto_collapse',
  'monochrome_labels',
  'password',
  'draft_context',
];
const AVAILABLE_LANGUAGES = ['auto', 'es-es', 'fr-fr', 'ja-jp', 'zh-cn', 'en-us', 'de-de', 'ko-kr', 'ru-ru', 'it-it'];

const computeImpactedUsers = async (context, user, roleId) => {
  // Get all groups that have this role
  const groupsRoles = await fullRelationsList(context, user, RELATION_HAS_ROLE, { toId: roleId, fromTypes: [ENTITY_TYPE_GROUP] });
  const groupIds = groupsRoles.map((group) => group.fromId);
  // Get all users for groups
  const usersGroups = await fullRelationsList(context, user, RELATION_MEMBER_OF, { toId: groupIds, toTypes: [ENTITY_TYPE_GROUP] });
  const userIds = R.uniq(usersGroups.map((u) => u.fromId));
  // Mark for refresh all impacted sessions
  return internalFindByIds(context, user, userIds);
};

const roleUsersCacheRefresh = async (context, user, roleId) => {
  const users = await computeImpactedUsers(context, user, roleId);
  await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, users, user);
};

export const userWithOrigin = (req, user) => {
  // /!\ This metadata information is used in different ways
  // - In audit logs to identify the user
  // - In stream message to also identifier the user
  // - In logging system to know the level of the error message

  // Additional header from "authentication with header" authentication mode
  const sso_headers_metadata = R.mergeAll((user.headers_audit ?? [])
    .map((header) => ({ [header]: req.header(header) })));
  const tracing_headers_metadata = getRequestAuditHeaders(req);

  const origin = {
    socket: 'query',
    ip: req?.ip,
    user_id: user.id,
    group_ids: user.groups?.map((g) => g.internal_id) ?? [],
    organization_ids: user.organizations?.map((o) => o.internal_id) ?? [],
    user_metadata: { ...sso_headers_metadata, ...tracing_headers_metadata },
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
    const memberOrganizations = await fullEntitiesThroughRelationsToList(context, user, userId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION);
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

const buildUserOrganizationRestrictedFilters = (user, filters) => {
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    // If user is not a set access administrator, user can only see attached organization users
    const organizationIds = user.administrated_organizations.map((organization) => organization.id);
    return {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'relationship_type',
              values: ['participate-to'],
            },
            {
              key: 'id',
              values: organizationIds,
            },
          ],
          mode: 'or',
        },
      ],
      filterGroups: filters && isFilterGroupNotEmpty(filters) ? [filters] : [],
    };
  }
  return filters;
};

export const findAllUser = async (context, user, args) => {
  const filters = buildUserOrganizationRestrictedFilters(user, args.filters);
  return fullEntitiesList(context, user, [ENTITY_TYPE_USER], { ...args, filters });
};

export const findUserPaginated = async (context, user, args) => {
  const filters = buildUserOrganizationRestrictedFilters(user, args.filters);
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_USER], { ...args, filters });
};

export const findCreators = (context, user, args) => {
  const { entityTypes = [] } = args;
  const creatorsFilter = async (creators) => { return filterMembersWithUsersOrgs(context, user, creators, FilterMembersMode.EXCLUDE); };
  return fullEntitiesThoughAggregationConnection(context, user, CREATOR_FILTER, ENTITY_TYPE_USER, { ...args, types: entityTypes, postResolveFilter: creatorsFilter });
};

export const findAssignees = (context, user, args) => {
  const { entityTypes = [] } = args;
  const assigneesFilter = async (assignees) => { return filterMembersWithUsersOrgs(context, user, assignees, FilterMembersMode.EXCLUDE); };
  return fullEntitiesThoughAggregationConnection(context, user, ASSIGNEE_FILTER, ENTITY_TYPE_USER, { ...args, types: entityTypes, postResolveFilter: assigneesFilter });
};
export const findParticipants = (context, user, args) => {
  const { entityTypes = [] } = args;
  const participantsFilter = async (participants) => { return filterMembersWithUsersOrgs(context, user, participants, FilterMembersMode.EXCLUDE); };
  return fullEntitiesThoughAggregationConnection(context, user, PARTICIPANT_FILTER, ENTITY_TYPE_USER, { ...args, types: entityTypes, postResolveFilter: participantsFilter });
};

export const findMembersPaginated = async (context, user, args) => {
  const { entityTypes = null } = args;
  const types = entityTypes || MEMBERS_ENTITY_TYPES;
  const restrictedArgs = await applyOrganizationRestriction(context, user, args);
  return pageEntitiesConnection(context, user, types, restrictedArgs);
};

export const findAllMembers = async (context, user, args) => {
  const { entityTypes = null } = args;
  const types = entityTypes || MEMBERS_ENTITY_TYPES;
  const restrictedArgs = await applyOrganizationRestriction(context, user, args);
  return fullEntitiesList(context, user, types, restrictedArgs);
};

export const findUserWithCapabilities = async (context, user, capabilities) => {
  const users = await getEntitiesListFromCache(context, user, ENTITY_TYPE_USER);
  return users.filter((u) => u.capabilities.some((userCapability) => capabilities.some((capability) => capability === userCapability.name)));
};

export const findAllSystemMemberPaginated = () => {
  const members = R.values(INTERNAL_USERS_WITHOUT_REDACTED);
  return buildPagination(0, null, members.map((r) => ({ node: r })), members.length);
};

// build only a creator object with what we need to expose of users
const buildCreatorUser = (user) => {
  if (!user) {
    return user;
  }
  return {
    id: user.id,
    entity_type: user.entity_type,
    name: ENABLED_DEMO_MODE ? REDACTED_USER.name : user.name,
    description: user.description,
    standard_id: user.id,
    [RELATION_PARTICIPATE_TO]: user[RELATION_PARTICIPATE_TO],
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

export const userOrganizationsPaginatedWithoutInferences = async (context, user, userId, opts) => {
  const args = { ...opts, withInferences: false };
  return pageRegardingEntitiesConnection(context, user, userId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION, false, args);
};

export const userOrganizationsPaginated = async (context, user, userId, opts) => {
  return pageRegardingEntitiesConnection(context, user, userId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION, false, opts);
};

// Get the creator of userId
export const getCreator = async (context, _user, userId) => {
  const allUsersInCache = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const userLoaded = allUsersInCache.get(userId);
  const firstCreatorId = Array.isArray(userLoaded.creator_id) && userLoaded.creator_id.length > 0
    ? userLoaded.creator_id.at(0)
    : userLoaded.creator_id;
  const userCreatorFromCache = allUsersInCache.get(firstCreatorId);
  return buildCreatorUser(userCreatorFromCache);
};

export const userRoles = async (context, _user, userId, opts) => {
  const { orderBy, orderMode } = opts;
  const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const userLoaded = platformUsers.get(userId);
  if (orderBy) {
    if (orderMode === 'desc') {
      return R.sortWith([R.descend(R.prop(orderBy))])(userLoaded.roles);
    }
    return R.sortWith([R.ascend(R.prop(orderBy))])(userLoaded.roles);
  }
  return userLoaded.roles;
};

export const userGroupsPaginated = async (context, user, userId, opts) => {
  return pageRegardingEntitiesConnection(context, user, userId, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP, false, opts);
};

export const groupRolesPaginated = async (context, user, groupId, opts) => {
  return pageRegardingEntitiesConnection(context, user, groupId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, false, opts);
};

export const batchRolesForUsers = async (context, user, userIds, opts = {}) => {
  // Get all groups for users
  const usersGroups = await fullRelationsList(context, user, RELATION_MEMBER_OF, { fromId: userIds, toTypes: [ENTITY_TYPE_GROUP] });
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
  const groupsRoles = await fullRelationsList(context, user, RELATION_HAS_ROLE, { fromId: groupIds, toTypes: [ENTITY_TYPE_ROLE] });
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
  const roles = await fullEntitiesList(context, user, [ENTITY_TYPE_ROLE], { ...opts, ids: roleIds });
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
    throw ForbiddenAccess('You are not allowed to share these markings', { markings: markingsToShare });
  }
};

const getUserAndGlobalMarkings = async (context, userId, userGroups, userMarkings, capabilities) => {
  const userCapabilities = capabilities.map((c) => c.name);
  const shouldBypass = userCapabilities.includes(BYPASS) || userId === OPENCTI_ADMIN_UUID;
  const allMarkingsPromise = getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const defaultGroupMarkingsPromise = defaultMarkingDefinitionsFromGroups(context, userGroups);
  let computeUserMarkings;
  let maxShareableMarkings;
  const [all, defaultMarkings] = await Promise.all([allMarkingsPromise, defaultGroupMarkingsPromise]);
  if (shouldBypass) { // Bypass user have all platform markings and can share all markings
    computeUserMarkings = all;
    maxShareableMarkings = all;
  } else { // Standard user have markings related to his groups
    computeUserMarkings = userMarkings;
    const notShareableMarkings = userGroups.flatMap(({ max_shareable_markings }) => max_shareable_markings?.filter(({ value }) => value === 'none').map(({ type }) => type));
    maxShareableMarkings = userGroups.flatMap(({ max_shareable_markings }) => max_shareable_markings?.filter(({ value }) => value !== 'none')).filter((m) => !!m);
    const allShareableMarkings = all.filter(({ definition_type }) => (
      !notShareableMarkings.includes(definition_type) && !maxShareableMarkings.some(({ type }) => type === definition_type)
    )).filter(({ id }) => computeUserMarkings.some((m) => m.id === id)).map(({ id }) => id);
    maxShareableMarkings = [...maxShareableMarkings.map(({ value }) => value), ...allShareableMarkings];
  }
  const computedMarkings = computeAvailableMarkings(computeUserMarkings, all);
  return { user: computedMarkings, default: defaultMarkings, max_shareable: await cleanMarkings(context, maxShareableMarkings) };
};

export const roleCapabilities = async (context, user, roleId) => {
  return fullEntitiesThroughRelationsToList(context, user, roleId, RELATION_HAS_CAPABILITY, ENTITY_TYPE_CAPABILITY);
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
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_ROLE], args);
};

export const findCapabilities = (context, user, args) => {
  const finalArgs = R.assoc('orderBy', 'attribute_order', args);
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_CAPABILITY], finalArgs);
};

export const roleDelete = async (context, user, roleId) => {
  const deleted = await deleteElementById(context, user, roleId, ENTITY_TYPE_ROLE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes role \`${deleted.name}\``,
    context_data: { id: roleId, entity_type: ENTITY_TYPE_ROLE, input: deleted }
  });
  await roleUsersCacheRefresh(context, user, roleId);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].DELETE_TOPIC, deleted, user).then(() => roleId);
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

const isUserAdministratingOrga = (user, organizationId) => {
  return user.administrated_organizations.some(({ id }) => id === organizationId);
};

export const assignOrganizationToUser = async (context, user, userId, organizationId) => {
  if (isOnlyOrgaAdmin(user)) {
    // When user is organization admin, we make sure she is also admin of organization added
    if (!isUserAdministratingOrga(user, organizationId)) {
      throw ForbiddenAccess();
    }
  }
  const targetUser = await findById(context, user, userId);
  if (!targetUser) {
    throw FunctionalError('Cannot add the relation, User cannot be found.', { userId });
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
    context_data: { id: targetUser.id, entity_type: ENTITY_TYPE_USER, input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, targetUser, user);
};

export const assignOrganizationNameToUser = async (context, user, userId, organizationName) => {
  const organization = { name: organizationName, identity_class: 'organization' };
  const generateToId = generateStandardId(ENTITY_TYPE_IDENTITY_ORGANIZATION, organization);
  return assignOrganizationToUser(context, user, userId, generateToId);
};

export const assignGroupToUser = async (context, user, userId, groupName) => {
  const targetUser = await findById(context, user, userId);
  if (!targetUser) {
    throw FunctionalError('Cannot add the relation, User cannot be found.', { userId });
  }
  // No need for audit log here, only use for provider login
  const generateToId = generateStandardId(ENTITY_TYPE_GROUP, { name: groupName });
  const assignInput = {
    fromId: userId,
    toId: generateToId,
    relationship_type: RELATION_MEMBER_OF,
  };
  const rel = await createRelation(context, user, assignInput);
  await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, targetUser, user);
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

export const sendEmailToUser = async (context, user, input) => {
  await checkEnterpriseEdition(context);
  const settings = await getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS);

  const users = await getEntitiesListFromCache(context, user, ENTITY_TYPE_USER);
  const targetUser = users.find((usr) => input.target_user_id === usr.id || input.target_user_id === usr.standard_id);

  if (!targetUser) {
    throw UnsupportedError('Target user not found', { id: input.target_user_id });
  }

  const organizationNames = (targetUser.organizations ?? []).map((org) => org.name);

  const emailTemplate = await internalLoadById(context, user, input.email_template_id);
  if (!emailTemplate || emailTemplate.entity_type !== ENTITY_TYPE_EMAIL_TEMPLATE) {
    throw UnsupportedError('Invalid email template', { id: input.email_template_id });
  }

  const preprocessedTemplate = emailTemplate.template_body
    .replace(/\$user\.firstname/g, '<%= user.firstname %>')
    .replace(/\$user\.lastname/g, '<%= user.lastname %>')
    .replace(/\$user\.name/g, '<%= user.name %>')
    .replace(/\$user\.user_email/g, '<%= user.user_email %>')
    .replace(/\$user\.api_token/g, '<%= user.api_token %>')
    .replace(/\$user\.account_status/g, '<%= user.account_status %>')
    .replace(/\$user\.objectOrganization/g, '<%= organizationNames.join(", ") %>')
    .replace(/\$user\.account_lock_after_date/g, '<%= user.account_lock_after_date %>')
    .replace(/\$settings\.platform_url/g, '<%= platformUrl %>');

  const platformUrl = settings.platform_url;

  const renderedHtml = ejs.render(preprocessedTemplate, {
    platformUrl,
    user: {
      ...targetUser,
      account_lock_after_date: targetUser.account_lock_after_date
        ? DateTime.fromISO(targetUser.account_lock_after_date).toFormat('yyyy-MM-dd')
        : ''
    },
    organizationNames,
  });

  const sendMailArgs = {
    from: `${emailTemplate.sender_email} <${settings.platform_email}>`,
    to: targetUser.user_email,
    subject: emailTemplate.email_object,
    html: renderedHtml,
  };

  await sendMail(sendMailArgs, {
    identifier: `user-${targetUser.id}`,
    category: 'user-notification',
  });
  await addUserEmailSendCount();
  await publishUserAction({
    user,
    event_type: 'command',
    event_scope: 'send',
    event_access: 'administration',
    context_data: {
      id: targetUser.id,
      entity_type: ENTITY_TYPE_USER,
      entity_name: targetUser.name,
      input: {
        ...input,
        to: targetUser.user_email
      }
    }
  });
  return true;
};

export const addUser = async (context, user, newUser) => {
  let userEmail;
  const userServiceAccount = newUser.user_service_account;
  if (newUser.user_email && !userServiceAccount) {
    userEmail = newUser.user_email.toLowerCase();
    const existingUser = await elLoadBy(context, SYSTEM_USER, 'user_email', userEmail, ENTITY_TYPE_USER);
    if (existingUser) {
      throw FunctionalError('User already exists', { user_id: existingUser.internal_id });
    }
  } else if (userServiceAccount) {
    userEmail = newUser.user_email ? newUser.user_email : `automatic+${uuid()}@opencti.invalid`;
  } else {
    throw FunctionalError('User cannot be created without email');
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
  if ((newUser.external === true && isEmptyField(userPassword)) || userServiceAccount) {
    userPassword = uuid();
  } else { // If local user, check the password policy
    await checkPasswordFromPolicy(context, userPassword);
  }
  let userToCreate = R.pipe(
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
    R.dissoc('groups'),
    R.dissoc('prevent_default_groups'),
    R.dissoc('email_template_id'),
  )(newUser);

  userToCreate = {
    ...userToCreate,
    user_service_account: newUser.user_service_account || false,
  };

  if (userServiceAccount) {
    userToCreate = {
      ...userToCreate,
      password: undefined,
    };
  }

  const { element, isCreation } = await createEntity(context, user, userToCreate, ENTITY_TYPE_USER, { complete: true });
  // Link to organizations
  const userOrganizations = newUser.objectOrganization ?? [];
  const relationOrganizations = userOrganizations.map((organizationId) => ({
    fromId: element.id,
    toId: organizationId,
    relationship_type: RELATION_PARTICIPATE_TO,
  }));
  await Promise.all(relationOrganizations.map((relation) => createRelation(context, user, relation)));
  // Add the provided groups
  let relationGroups = [];
  if ((newUser.groups ?? []).length > 0) {
    relationGroups = (newUser.groups ?? []).map((group) => ({
      fromId: element.id,
      toId: group,
      relationship_type: RELATION_MEMBER_OF,
    }));
  }
  // if prevent_default_groups is not true, assign the default groups to the user
  if (newUser.prevent_default_groups !== true) {
    const defaultAssignationFilter = {
      mode: 'and',
      filters: [{ key: 'default_assignation', values: [true] }],
      filterGroups: [],
    };
    const defaultGroups = await findGroups(context, user, { filters: defaultAssignationFilter });
    const relationDefaultGroups = defaultGroups.edges
      .filter((e) => !(newUser.groups ?? []).includes(e.node.internal_id)) // remove groups already in new user group input
      .map((e) => ({
        fromId: element.id,
        toId: e.node.internal_id,
        relationship_type: RELATION_MEMBER_OF,
      }));
    relationGroups = [...relationGroups, ...relationDefaultGroups];
  }
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

  await notify(BUS_TOPICS[ENTITY_TYPE_USER].ADDED_TOPIC, element, user);
  if (newUser.email_template_id) {
    const input = {
      target_user_id: element.id,
      email_template_id: newUser.email_template_id,
    };
    try {
      await sendEmailToUser(context, user, input);
    } catch (_err) {
      logApp.error('Error sending email on user creation', { createdUserID: user.id, emailTemplateId: newUser.email_template_id });
    }
  }
  return element;
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
  await roleUsersCacheRefresh(context, user, roleId);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, element, user);
};

export const roleAddRelation = async (context, user, roleId, input) => {
  const role = await storeLoadById(context, user, roleId, ENTITY_TYPE_ROLE);
  if (!role) {
    throw FunctionalError(`Cannot add the relation, ${ENTITY_TYPE_ROLE} cannot be found.`, { id: roleId });
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
  await roleUsersCacheRefresh(context, user, roleId);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, relationData, user);
};

export const roleDeleteRelation = async (context, user, roleId, toId, relationshipType) => {
  const role = await storeLoadById(context, user, roleId, ENTITY_TYPE_ROLE);
  if (!role) {
    throw FunctionalError('Cannot delete the relation, Role cannot be found.', { id: roleId });
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method, got ${relationshipType}.`);
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
  await roleUsersCacheRefresh(context, user, roleId);
  return notify(BUS_TOPICS[ENTITY_TYPE_ROLE].EDIT_TOPIC, role, user);
};

// User related
export const userEditField = async (context, user, userId, rawInputs) => {
  const inputs = [];
  const userToUpdate = await internalLoadById(context, user, userId);
  // Check in an organization admin edits a user that's not in its administrated organizations
  const myAdministratedOrganizationsIds = user.administrated_organizations.map((orga) => orga.id);
  if (isOnlyOrgaAdmin(user)) {
    if (userId !== user.id && !userToUpdate[RELATION_PARTICIPATE_TO].find((orga) => myAdministratedOrganizationsIds.includes(orga))) {
      throw ForbiddenAccess();
    }
  }
  let skipThisInput = false;
  for (let index = 0; index < rawInputs.length; index += 1) {
    const input = rawInputs[index];
    if (userToUpdate.external && input.key === 'name') {
      throw FunctionalError('Name cannot be updated for external user', { userId });
    }
    if (userToUpdate.external && input.key === 'user_email') {
      throw FunctionalError('Email cannot be updated for external user', { userId });
    }
    if (input.key === 'password') {
      const userServiceAccountInput = rawInputs.find((x) => x.key === 'user_service_account');
      if (userServiceAccountInput && userToUpdate.user_service_account !== userServiceAccountInput.value[0]) {
        skipThisInput = true;
      }

      if (!userToUpdate.user_service_account) {
        const userPassword = R.head(input.value).toString();
        await checkPasswordFromPolicy(context, userPassword);
        input.value = [bcrypt.hashSync(userPassword)];
      } else {
        throw FunctionalError('Cannot update password for Service account', { userId });
      }
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
    if (input.key === 'draft_context') {
      // draft context might have changed, we need to check draft context exists and refresh session info
      const draftContext = R.head(input.value)?.toString();
      if (draftContext?.length > 0) {
        const draftWorkspaces = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
        const draftWorkspace = draftWorkspaces.get(draftContext);
        if (!draftWorkspace) throw DraftLockedError('Could not find draft workspace');
        if (draftWorkspace.draft_status !== DRAFT_STATUS_OPEN) throw DraftLockedError('Can not move to a draft not in an open state');
      }
    }
    if (input.key === 'unit_system') {
      const unit = R.head(input.value).toString();
      if (!Object.keys(UnitSystem).map((option) => option.toLowerCase()).includes(unit.toLowerCase())) {
        throw UnsupportedError('Unsupported unit system', { unit });
      }
    }
    // Check language is valid in case of language change
    if (input.key === 'language') {
      if (!(input.value.length === 1 && AVAILABLE_LANGUAGES.includes(input.value[0]))) {
        throw FunctionalError('The language you have provided is not valid');
      }
    }

    // Turn User into Service Account
    if (input.key === 'user_service_account' && !userToUpdate.user_service_account && input.value[0] === true) {
      inputs.push({ key: 'password', value: [null] });
      await addUserIntoServiceAccountCount();
    }
    // Turn Service Account into User
    if (input.key === 'user_service_account' && userToUpdate.user_service_account && input.value[0] === false) {
      const userPassword = uuid();
      await checkPasswordFromPolicy(context, userPassword);
      inputs.push({ key: 'password', value: [bcrypt.hashSync(userPassword)] });
      await addServiceAccountIntoUserCount();
    }

    if (!skipThisInput) {
      inputs.push(input);
    }
  }
  const { element } = await updateAttribute(context, user, userId, ENTITY_TYPE_USER, inputs);
  const input = updatedInputsToData(element, inputs);
  const personalUpdate = user.id === userId;
  const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : element.user_email;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${inputs.map((i) => i.key).join(', ')}\` for ${personalUpdate ? '`themselves`' : `user \`${actionEmail}\``}`,
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

export const meEditField = async (context, user, userId, inputs, password = null) => {
  inputs.forEach((input) => {
    const { key } = input;
    // Check if field can be updated by the user
    if (PROTECTED_USER_ATTRIBUTES.includes(key)) {
      throw ForbiddenAccess();
    }
    // If the user is external, some extra attributes must be protected
    if (user.external && PROTECTED_EXTERNAL_ATTRIBUTES.includes(key)) {
      throw ForbiddenAccess();
    }
    // On MeUser only some fields are updatable
    if (!ME_USER_MODIFIABLE_ATTRIBUTES.includes(key)) {
      throw ForbiddenAccess();
    }
    // Check password confirmation in case of password change
    if (key === 'password') {
      const dbPassword = user.password;
      const match = bcrypt.compareSync(password, dbPassword);
      if (!match) {
        throw FunctionalError('The current password you have provided is not valid');
      }
    }
  });
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

  const workspacesToDelete = await fullEntitiesList(context, userToDeleteAuth, [ENTITY_TYPE_WORKSPACE]);

  const workspaceToDeleteIds = workspacesToDelete
    .filter((workspaceEntity) => isUserTheLastAdmin(userId, workspaceEntity.restricted_members))
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
            {
              nested: {
                path: authorizedMembers.name,
                query: {
                  term: { [`${authorizedMembers.name}.id.keyword`]: { value: userId } }
                }
              }
            }
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
  if (isOnlyOrgaAdmin(user)) {
    // When user is organization admin, we make sure that the deleted user is in one of the administrated organizations of the admin
    const userData = await storeLoadById(context, user, userId, ENTITY_TYPE_USER);
    const myAdministratedOrganizationsIds = user.administrated_organizations.map(({ id }) => id);
    if (!userData[RELATION_PARTICIPATE_TO].find((orga) => myAdministratedOrganizationsIds.includes(orga))) {
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
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].DELETE_TOPIC, deleted, user).then(() => userId);
};

export const userAddRelation = async (context, user, userId, input) => {
  const userData = await storeLoadById(context, user, userId, ENTITY_TYPE_USER);
  if (!userData) {
    throw FunctionalError(`Cannot add the relation, ${ENTITY_TYPE_USER} cannot be found.`, { userId });
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method, got ${input.relationship_type}.`);
  }
  // Check in case organization admins adds non-grantable goup a user
  const myGrantableGroups = R.uniq(user.administrated_organizations.map((orga) => orga.grantable_groups).flat());
  if (isOnlyOrgaAdmin(user)) {
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
    context_data: { id: userData.id, entity_type: ENTITY_TYPE_USER, input: finalInput }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, userData, user).then(() => relationData);
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
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, targetUser, user);
};

export const userIdDeleteRelation = async (context, user, userId, toId, relationshipType) => {
  const userData = await storeLoadById(context, user, userId, ENTITY_TYPE_USER);
  if (!userData) {
    throw FunctionalError('Cannot delete the relation, User cannot be found.', { userId });
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method, got ${relationshipType}.`);
  }
  return userDeleteRelation(context, user, userData, toId, relationshipType);
};

export const userDeleteOrganizationRelation = async (context, user, userId, toId) => {
  if (isOnlyOrgaAdmin(user)) {
    // When user is organization admin, we make sure she is also admin of organization removed
    if (!isUserAdministratingOrga(user, toId)) {
      throw ForbiddenAccess();
    }
  }
  const targetUser = await findById(context, user, userId);
  if (!targetUser) {
    throw FunctionalError('Cannot delete the relation, User cannot be found.', { userId });
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
    context_data: { id: targetUser.id, entity_type: ENTITY_TYPE_USER, input }
  });
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
  const userEmail = email.toLowerCase();
  const name = isEmptyField(providedName) ? userEmail : providedName;
  const user = await elLoadBy(context, SYSTEM_USER, 'user_email', userEmail, ENTITY_TYPE_USER);
  if (!user) {
    // If user doesn't exist, create it. Providers are trusted
    const newUser = { name, firstname, lastname, user_email: userEmail, external: true };
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
    const userGroups = await fullEntitiesThroughRelationsToList(context, SYSTEM_USER, user.id, RELATION_MEMBER_OF, ENTITY_TYPE_GROUP);
    const deleteGroups = userGroups.filter((o) => !providerGroups.includes(o.name));
    for (let index = 0; index < deleteGroups.length; index += 1) {
      const deleteGroup = deleteGroups[index];
      await userDeleteRelation(context, SYSTEM_USER, user, deleteGroup.id, RELATION_MEMBER_OF);
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
    const userOrganizations = await fullEntitiesThroughRelationsToList(context, SYSTEM_USER, user.id, RELATION_PARTICIPATE_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION);
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

export const getUserByEmail = async (email) => {
  const context = executionContext('login');
  return await elLoadBy(context, SYSTEM_USER, 'user_email', email, ENTITY_TYPE_USER);
};

export const login = async (email, password) => {
  const user = await getUserByEmail(email);
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
  const targetUser = await findById(context, user, user.id);
  const individualInput = { name: targetUser.name, contact_information: targetUser.user_email };
  // We need to bypass validation here has we maybe not setup all require fields
  const individual = await addIndividual(context, targetUser, individualInput, { bypassValidation: true });
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, targetUser, user).then(() => individual);
};

export const resolveUserIndividual = async (context, user) => {
  if (INTERNAL_USERS[user.id]) {
    return undefined;
  }
  if (user.individual_id === undefined) {
    const individual = await userAddIndividual(context, user);
    return individual.id;
  }
  return user.individual_id;
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
    return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, element, user);
  }
  throw AuthenticationFailure();
};

export const otpUserDeactivation = async (context, user, id) => {
  if (!context.user_with_session) {
    throw UnsupportedError('You need to deactivate your current 2FA in a valid user session');
  }
  const patch = { otp_activated: false, otp_secret: '', otp_qr: '' };
  const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_USER, patch);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, element, user);
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
  req.session.save();
  return isValidated;
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

export const isSensitiveChangesAllowed = (userId, roles) => {
  if (userId === OPENCTI_ADMIN_UUID) {
    return true;
  }
  return roles.some(({ can_manage_sensitive_config }) => can_manage_sensitive_config);
};

export const buildCompleteUsers = async (context, clients) => {
  const resolvedUsers = [];
  const markingsMap = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const contactInformationFilter = { mode: 'and', filters: [{ key: 'contact_information', values: clients.map((c) => c.user_email) }], filterGroups: [] };
  const individualArgs = { indices: [READ_INDEX_STIX_DOMAIN_OBJECTS], filters: contactInformationFilter, noFiltersChecking: true };
  const individualsPromise = fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_IDENTITY_INDIVIDUAL], individualArgs);
  const authRelationships = [RELATION_PARTICIPATE_TO, RELATION_MEMBER_OF, RELATION_HAS_CAPABILITY, RELATION_HAS_ROLE, RELATION_ACCESSES_TO];
  const relations = await fullRelationsList(context, SYSTEM_USER, authRelationships, { indices: READ_RELATIONSHIPS_INDICES });
  const users = new Map();
  const roleIds = new Set();
  const groupIds = new Set();
  const capabilityIds = new Set();
  const organizationIds = new Set();
  const groupsRoles = new Map();
  const groupsMarkings = new Map();
  const rolesCapabilities = new Map();
  for (let index = 0; index < relations.length; index += 1) {
    await doYield();
    const { fromId, entity_type, toId } = relations[index];
    // group <- RELATION_ACCESSES_TO -> marking
    if (entity_type === RELATION_ACCESSES_TO) {
      if (groupsMarkings.has(fromId)) {
        const markings = groupsMarkings.get(fromId);
        groupsMarkings.set(fromId, [...(markings ?? []), toId]);
      } else {
        groupsMarkings.set(fromId, [toId]);
      }
    }
    // user <- RELATION_PARTICIPATE_TO -> organization
    if (entity_type === RELATION_PARTICIPATE_TO) {
      organizationIds.add(toId);
      if (users.has(fromId)) {
        const user = users.get(fromId);
        if (user.organizationIds) {
          user.organizationIds.push(toId);
        } else {
          user.organizationIds = [toId];
        }
        users.set(fromId, user);
      } else {
        users.set(fromId, { organizationIds: [toId] });
      }
    }
    // user <- RELATION_MEMBER_OF -> group
    if (entity_type === RELATION_MEMBER_OF) {
      groupIds.add(toId);
      if (users.has(fromId)) {
        const user = users.get(fromId);
        if (user.groupIds) {
          user.groupIds.push(toId);
        } else {
          user.groupIds = [toId];
        }
        users.set(fromId, user);
      } else {
        users.set(fromId, { groupIds: [toId] });
      }
    }
    // role <- RELATION_HAS_CAPABILITY -> capability
    if (entity_type === RELATION_HAS_CAPABILITY) {
      roleIds.add(fromId);
      capabilityIds.add(toId);
      if (rolesCapabilities.has(fromId)) {
        const capabilities = rolesCapabilities.get(fromId);
        rolesCapabilities.set(fromId, [...(capabilities ?? []), toId]);
      } else {
        rolesCapabilities.set(fromId, [toId]);
      }
    }
    // group <- RELATION_HAS_ROLE -> role
    if (entity_type === RELATION_HAS_ROLE) {
      groupIds.add(fromId);
      roleIds.add(toId);
      if (groupsRoles.has(fromId)) {
        const roles = groupsRoles.get(fromId);
        groupsRoles.set(fromId, [...(roles ?? []), toId]);
      } else {
        groupsRoles.set(fromId, [toId]);
      }
    }
  }
  const ids = [...Array.from(groupIds), ...Array.from(roleIds), ...Array.from(organizationIds), ...Array.from(capabilityIds)];
  const resolvedObject = await internalFindByIds(context, SYSTEM_USER, ids, { toMap: true });
  const individuals = await individualsPromise;
  const individualMap = new Map();
  for (let indexIndividual = 0; indexIndividual < individuals.length; indexIndividual += 1) {
    const individual = individuals[indexIndividual];
    individualMap.set(individual.contact_information, individual);
  }
  for (let userIndex = 0; userIndex < clients.length; userIndex += 1) {
    const client = clients[userIndex];
    const user = users.get(client.internal_id);
    const groups = (user?.groupIds ?? []).map((groupId) => resolvedObject[groupId])
      .filter((e) => isNotEmptyField(e));
    const roles = R.uniq(groups.map((group) => groupsRoles.get(group.internal_id)).flat())
      .map((roleId) => resolvedObject[roleId]).filter((e) => isNotEmptyField(e));
    const markings = R.uniq(groups.map((group) => groupsMarkings.get(group.internal_id)).flat())
      .map((markingId) => markingsMap.get(markingId)).filter((e) => isNotEmptyField(e));
    const canManageSensitiveConfig = { can_manage_sensitive_config: isSensitiveChangesAllowed(client.id, roles) };
    const capabilities = R.uniq(roles.map((role) => rolesCapabilities.get(role.internal_id)).flat())
      .map((capabilityId) => resolvedObject[capabilityId]).filter((e) => isNotEmptyField(e));
    // Force push the bypass for default admin
    const withoutBypass = !capabilities.some((c) => c.name === BYPASS);
    if (client.internal_id === OPENCTI_ADMIN_UUID && withoutBypass) {
      const id = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: BYPASS });
      capabilities.push({ id, standard_id: id, internal_id: id, name: BYPASS });
    }
    const isByPass = R.find((s) => s.name === BYPASS, capabilities) !== undefined;
    const organizations = (user?.organizationIds ?? []).map((organizationId) => resolvedObject[organizationId])
      .filter((e) => isNotEmptyField(e) && e.entity_type === ENTITY_TYPE_IDENTITY_ORGANIZATION);
    const defaultHiddenTypesGroups = getDefaultHiddenTypes(groups);
    const defaultHiddenTypesOrgs = getDefaultHiddenTypes(organizations);
    const default_hidden_types = uniq(defaultHiddenTypesGroups.concat(defaultHiddenTypesOrgs));
    const administrated_organizations = organizations.filter((o) => (o.authorized_authorities ?? []).includes(client.id));
    const effective_confidence_level = computeUserEffectiveConfidenceLevel({ ...client, groups, capabilities });
    const no_creators = groups.filter((g) => g.no_creators).length === groups.length;
    const restrict_delete = !isByPass && groups.filter((g) => g.restrict_delete).length === groups.length;
    const marking = await getUserAndGlobalMarkings(context, client.id, groups, markings, capabilities);
    if (administrated_organizations.length > 0) {
      capabilities.push(virtualOrganizationAdminCapability);
    }
    resolvedUsers.push({
      ...client,
      ...canManageSensitiveConfig,
      roles,
      capabilities,
      default_hidden_types,
      groups,
      organizations,
      administrated_organizations,
      otp_activated: client.otp_activated ?? false,
      individual_id: individualMap.get(client.user_email)?.internal_id,
      effective_confidence_level,
      no_creators,
      restrict_delete,
      allowed_marking: marking.user,
      default_marking: marking.default,
      max_shareable_marking: marking.max_shareable,
    });
  }
  return resolvedUsers;
};

export const buildCompleteUser = async (context, client) => {
  if (!client) {
    return undefined;
  }
  const users = await buildCompleteUsers(context, [client]);
  return users[0];
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

export const authenticateUserByTokenOrUserId = async (context, req, tokenOrId) => {
  const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  if (platformUsers.has(tokenOrId)) {
    let authenticatedUser = platformUsers.get(tokenOrId);
    const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    const applicantId = req.headers['opencti-applicant-id'];
    if (applicantId && isBypassUser(authenticatedUser)) {
      authenticatedUser = platformUsers.get(applicantId) || INTERNAL_USERS[applicantId];
      if (!authenticatedUser) {
        throw FunctionalError(`Cant impersonate applicant ${applicantId}`);
      }
    }
    validateUser(authenticatedUser, settings);
    return userWithOrigin(req, authenticatedUser);
  }
  throw FunctionalError(`Cant identify with ${tokenOrId}`);
};

export const userRenewToken = async (context, user, userId) => {
  if (userId === OPENCTI_ADMIN_UUID) {
    throw FunctionalError('Cannot renew token of admin user defined in configuration, please change configuration instead.');
  }

  const userData = await storeLoadById(context, user, userId, ENTITY_TYPE_USER);
  if (!userData) {
    throw FunctionalError(`Cannot renew token, ${userId} user cannot be found.`);
  }
  const patch = { api_token: uuid() };
  const { element } = await patchAttribute(context, user, userId, ENTITY_TYPE_USER, patch);

  const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : userData.user_email;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `renew token of user \`${actionEmail}\``,
    context_data: { id: userId, entity_type: ENTITY_TYPE_USER }
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, element, user);
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
  if (!hasSetAccessCapability && settings.platform_organization && user.organizations.length === 0 && !user.user_service_account) {
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

export const sessionAuthenticateUser = async (context, req, user, provider) => {
  let platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  let logged = platformUsers.get(user.internal_id);
  if (!logged) {
    logApp.warn('[CACHE] Missing user in cache', { user: user.internal_id });
    // Ensure all nodes known about this user
    await notify(BUS_TOPICS[ENTITY_TYPE_USER].ADDED_TOPIC, user, user);
    // Get the user in a refreshed cache
    platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
    logged = platformUsers.get(user.internal_id);
  }
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  validateUser(logged, settings);
  // Build and save the session
  req.session.user = { id: user.id, session_creation: now(), otp_validated: false };
  req.session.session_provider = provider;
  req.session.save();
  // Publish the login event
  const userOrigin = userWithOrigin(req, logged);
  await publishUserAction({
    user: userOrigin,
    event_type: 'authentication',
    event_access: 'administration',
    event_scope: 'login',
    context_data: { provider }
  });
  return userOrigin;
};

export const HEADERS_AUTHENTICATORS = [];
// This method can only be used in createAuthenticatedContext
// If you need to check auth and create context, use directly createAuthenticatedContext method
export const authenticateUserFromRequest = async (context, req) => {
  const sessionUser = req.session?.user;
  // region If user already have a session
  if (sessionUser) {
    const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
    const logged = platformUsers.get(sessionUser.id);
    const authUser = { ...sessionUser, ...logged };
    return userWithOrigin(req, authUser);
  }
  // endregion
  // region Direct authentication
  // If user not identified, try headers authentication
  if (HEADERS_AUTHENTICATORS.length > 0) {
    for (let i = 0; i < HEADERS_AUTHENTICATORS.length; i += 1) {
      const headProvider = HEADERS_AUTHENTICATORS[i];
      const user = await headProvider.reqLoginHandler(req);
      if (user) {
        return await authenticateUserByTokenOrUserId(context, req, user.id);
      }
    }
  }
  // If user not identified, try to extract token from bearer
  let tokenUUID = extractTokenFromBearer(req.headers.authorization);
  // If no bearer specified, try with basic auth
  if (!tokenUUID) {
    tokenUUID = await extractTokenFromBasicAuth(req.headers.authorization);
  }
  // Get user from the token if found
  if (tokenUUID) {
    try {
      return await authenticateUserByTokenOrUserId(context, req, tokenUUID);
    } catch (err) {
      logApp.warn('Error resolving user by token', { cause: err });
    }
  }
  // endregion
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
