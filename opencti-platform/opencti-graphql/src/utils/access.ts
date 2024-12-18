import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import type { Context, Span, Tracer } from '@opentelemetry/api';
import { context as telemetryContext, trace } from '@opentelemetry/api';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS, isInternalObject } from '../schema/internalObject';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { AuthContext, AuthUser, UserRole } from '../types/user';
import type { BasicStoreCommon } from '../types/store';
import type { StixObject } from '../types/stix-common';
import { STIX_ORGANIZATIONS_UNRESTRICTED } from '../schema/stixDomainObject';
import { generateInternalType, getParentTypes } from '../schema/schemaUtils';
import { telemetry } from '../config/tracing';
import type { BasicStoreSettings } from '../types/settings';
import { ACCOUNT_STATUS_ACTIVE } from '../config/conf';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { FunctionalError } from '../config/errors';
import { isNotEmptyField } from '../database/utils';
import { isStixObject } from '../schema/stixCoreObject';

export const DEFAULT_INVALID_CONF_VALUE = 'ChangeMe';

export const BYPASS = 'BYPASS';
export const KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE = 'KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE';
export const KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS = 'KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS';
export const SETTINGS_SET_ACCESSES = 'SETTINGS_SETACCESSES';
export const SETTINGS_SUPPORT = 'SETTINGS_SUPPORT';
export const TAXIIAPI_SETCOLLECTIONS = 'TAXIIAPI_SETCOLLECTIONS';
export const CSVMAPPERS = 'CSVMAPPERS';
export const KNOWLEDGE = 'KNOWLEDGE';
export const KNOWLEDGE_KNUPDATE = 'KNOWLEDGE_KNUPDATE';
export const KNOWLEDGE_ORGANIZATION_RESTRICT = 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT';
export const KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS = 'KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS';
export const KNOWLEDGE_KNASKIMPORT = 'KNOWLEDGE_KNASKIMPORT';
export const VIRTUAL_ORGANIZATION_ADMIN = 'VIRTUAL_ORGANIZATION_ADMIN';
export const SETTINGS_SETACCESSES = 'SETTINGS_SETACCESSES';
export const SETTINGS_SECURITYACTIVITY = 'SETTINGS_SECURITYACTIVITY';
export const SETTINGS_SETLABELS = 'SETTINGS_SETLABELS';

export const ROLE_DEFAULT = 'Default';
export const ROLE_ADMINISTRATOR = 'Administrator';
const RETENTION_MANAGER_USER_UUID = '82ed2c6c-eb27-498e-b904-4f2abc04e05f';
export const RULE_MANAGER_USER_UUID = 'f9d7b43f-b208-4c56-8637-375a1ce84943';
export const AUTOMATION_MANAGER_USER_UUID = 'c49fe040-2dad-412d-af07-ce639204ad55';
export const DECAY_MANAGER_USER_UUID = '7f176d74-9084-4d23-8138-22ac78549547';
export const GARBAGE_COLLECTION_MANAGER_USER_UUID = 'c30d12be-d5fb-4724-88e7-8a7c9a4516c2';
const TELEMETRY_MANAGER_USER_UUID = 'c30d12be-d5fb-4724-88e7-8a7c9a4516c3';
export const REDACTED_USER_UUID = '31afac4e-6b99-44a0-b91b-e04738d31461';

export const MEMBER_ACCESS_ALL = 'ALL';
export const MEMBER_ACCESS_CREATOR = 'CREATOR';
export const MEMBER_ACCESS_RIGHT_ADMIN = 'admin';
export const MEMBER_ACCESS_RIGHT_EDIT = 'edit';
export const MEMBER_ACCESS_RIGHT_VIEW = 'view';
const MEMBER_ACCESS_RIGHTS = [MEMBER_ACCESS_RIGHT_VIEW, MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_ADMIN];

type ObjectWithCreators = {
  id: string,
  entity_type: string,
  creator_id?: string | string[] | undefined
};

const administratorRoleId = uuidv4();
export const ADMINISTRATOR_ROLE: UserRole = {
  id: administratorRoleId,
  internal_id: administratorRoleId,
  name: ROLE_ADMINISTRATOR
};

const defaultRoleId = uuidv4();
export const DEFAULT_ROLE: UserRole = {
  id: defaultRoleId,
  internal_id: defaultRoleId,
  name: ROLE_DEFAULT
};

export const SYSTEM_USER: AuthUser = {
  entity_type: 'User',
  id: OPENCTI_SYSTEM_UUID,
  internal_id: OPENCTI_SYSTEM_UUID,
  individual_id: undefined,
  name: 'SYSTEM',
  user_email: 'SYSTEM',
  inside_platform_organization: true,
  origin: { user_id: OPENCTI_SYSTEM_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  default_marking: [],
  max_shareable_marking: [],
  all_marking: [],
  api_token: '',
  account_lock_after_date: undefined,
  account_status: ACCOUNT_STATUS_ACTIVE,
  administrated_organizations: [],
  effective_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  user_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  no_creators: false,
  restrict_delete: false,
};

export const RETENTION_MANAGER_USER: AuthUser = {
  entity_type: 'User',
  id: RETENTION_MANAGER_USER_UUID,
  internal_id: RETENTION_MANAGER_USER_UUID,
  individual_id: undefined,
  name: 'RETENTION MANAGER',
  user_email: 'RETENTION MANAGER',
  inside_platform_organization: true,
  origin: { user_id: RETENTION_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
  all_marking: [],
  api_token: '',
  account_lock_after_date: undefined,
  account_status: ACCOUNT_STATUS_ACTIVE,
  administrated_organizations: [],
  effective_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  user_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  no_creators: false,
  restrict_delete: false,
};

export const RULE_MANAGER_USER: AuthUser = {
  entity_type: 'User',
  id: RULE_MANAGER_USER_UUID,
  internal_id: RULE_MANAGER_USER_UUID,
  individual_id: undefined,
  name: 'RULE MANAGER',
  user_email: 'RULE MANAGER',
  inside_platform_organization: true,
  origin: { user_id: RULE_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
  all_marking: [],
  api_token: '',
  account_lock_after_date: undefined,
  account_status: ACCOUNT_STATUS_ACTIVE,
  administrated_organizations: [],
  effective_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  user_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  no_creators: false,
  restrict_delete: false,
};

export const AUTOMATION_MANAGER_USER: AuthUser = {
  entity_type: 'User',
  id: AUTOMATION_MANAGER_USER_UUID,
  internal_id: AUTOMATION_MANAGER_USER_UUID,
  individual_id: undefined,
  name: 'AUTOMATION MANAGER',
  user_email: 'AUTOMATION MANAGER',
  inside_platform_organization: true,
  origin: { user_id: AUTOMATION_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
  all_marking: [],
  api_token: '',
  account_lock_after_date: undefined,
  account_status: ACCOUNT_STATUS_ACTIVE,
  administrated_organizations: [],
  effective_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  user_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  no_creators: false,
  restrict_delete: false,
};

export const DECAY_MANAGER_USER: AuthUser = {
  entity_type: 'User',
  id: DECAY_MANAGER_USER_UUID,
  internal_id: DECAY_MANAGER_USER_UUID,
  individual_id: undefined,
  name: 'DECAY MANAGER',
  user_email: 'DECAY MANAGER',
  inside_platform_organization: true,
  origin: { user_id: DECAY_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
  all_marking: [],
  api_token: '',
  account_lock_after_date: undefined,
  account_status: ACCOUNT_STATUS_ACTIVE,
  administrated_organizations: [],
  effective_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  user_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  no_creators: false,
  restrict_delete: false,
};

export const GARBAGE_COLLECTION_MANAGER_USER: AuthUser = {
  entity_type: 'User',
  id: GARBAGE_COLLECTION_MANAGER_USER_UUID,
  internal_id: GARBAGE_COLLECTION_MANAGER_USER_UUID,
  individual_id: undefined,
  name: 'GARBAGE_COLLECTION MANAGER',
  user_email: 'GARBAGE COLLECTION MANAGER',
  inside_platform_organization: true,
  origin: { user_id: GARBAGE_COLLECTION_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
  all_marking: [],
  api_token: '',
  account_lock_after_date: undefined,
  account_status: ACCOUNT_STATUS_ACTIVE,
  administrated_organizations: [],
  effective_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  user_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  no_creators: false,
  restrict_delete: false,
};

export const REDACTED_USER: AuthUser = {
  administrated_organizations: [],
  entity_type: 'User',
  id: REDACTED_USER_UUID,
  internal_id: REDACTED_USER_UUID,
  individual_id: undefined,
  name: '*** Redacted ***',
  user_email: '*** Redacted ***',
  inside_platform_organization: false,
  origin: { user_id: REDACTED_USER_UUID, socket: 'internal' },
  roles: [],
  groups: [],
  capabilities: [],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
  all_marking: [],
  api_token: '',
  account_lock_after_date: undefined,
  account_status: ACCOUNT_STATUS_ACTIVE,
  effective_confidence_level: null,
  user_confidence_level: null,
  no_creators: false,
  restrict_delete: false,
};

export const TELEMETRY_MANAGER_USER: AuthUser = {
  entity_type: 'User',
  id: TELEMETRY_MANAGER_USER_UUID,
  internal_id: TELEMETRY_MANAGER_USER_UUID,
  individual_id: undefined,
  name: 'TELEMETRY MANAGER',
  user_email: 'TELEMETRY MANAGER',
  inside_platform_organization: true,
  origin: { user_id: TELEMETRY_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
  all_marking: [],
  api_token: '',
  account_lock_after_date: undefined,
  account_status: ACCOUNT_STATUS_ACTIVE,
  administrated_organizations: [],
  effective_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  user_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  no_creators: false,
  restrict_delete: false,
};
export interface AuthorizedMember { id: string, access_right: string }

class TracingContext {
  ctx: Context | undefined;

  tracer: Tracer;

  constructor(tracer: Tracer) {
    this.tracer = tracer;
    this.ctx = undefined;
  }

  getCtx() {
    return this.ctx;
  }

  getTracer() {
    return this.tracer;
  }

  setCurrentCtx(span: Span) {
    this.ctx = trace.setSpan(telemetryContext.active(), span);
  }
}

export const executionContext = (source: string, auth?: AuthUser): AuthContext => {
  const tracer = trace.getTracer('instrumentation-opencti', '1.0.0');
  const tracing = new TracingContext(tracer);
  return { otp_mandatory: false, source, tracing, user: auth ?? undefined };
};

export const INTERNAL_USERS = {
  [SYSTEM_USER.id]: SYSTEM_USER,
  [RETENTION_MANAGER_USER.id]: RETENTION_MANAGER_USER,
  [RULE_MANAGER_USER.id]: RULE_MANAGER_USER,
  [AUTOMATION_MANAGER_USER.id]: AUTOMATION_MANAGER_USER,
  [DECAY_MANAGER_USER.id]: DECAY_MANAGER_USER,
  [REDACTED_USER.id]: REDACTED_USER
};

export const INTERNAL_USERS_WITHOUT_REDACTED = {
  [SYSTEM_USER.id]: SYSTEM_USER,
  [RETENTION_MANAGER_USER.id]: RETENTION_MANAGER_USER,
  [RULE_MANAGER_USER.id]: RULE_MANAGER_USER,
  [AUTOMATION_MANAGER_USER.id]: AUTOMATION_MANAGER_USER,
  [DECAY_MANAGER_USER.id]: DECAY_MANAGER_USER,
};

export const isBypassUser = (user: AuthUser): boolean => {
  return R.find((s) => s.name === BYPASS, user.capabilities || []) !== undefined;
};

export const isUserHasCapability = (user: AuthUser, capability: string): boolean => {
  return isBypassUser(user) || (user.capabilities || []).some((s) => capability !== BYPASS && s.name.includes(capability));
};

export const isUserHasCapabilities = (user: AuthUser, capabilities: string[] = []) => {
  return capabilities.every((capability) => isUserHasCapability(user, capability));
};

export const isOnlyOrgaAdmin = (user: AuthUser) => {
  return !isUserHasCapability(user, SETTINGS_SET_ACCESSES) && isUserHasCapability(user, VIRTUAL_ORGANIZATION_ADMIN);
};

export const isOrganizationAllowed = (element: BasicStoreCommon, user: AuthUser, settings:BasicStoreSettings) => {
  const elementOrganizations = element[RELATION_GRANTED_TO] ?? [];

  // If platform organization is set
  if (settings.platform_organization) {
    const userOrganizations = user.allowed_organizations.map((o) => o.internal_id);

    // If user part of platform organization, is granted by default
    if (user.inside_platform_organization) {
      return true;
    }
    // Grant access to the user individual
    if (element.internal_id === user.individual_id) {
      return true;
    }
    // If not, user is by design inside an organization
    // If element has no current sharing organization, it can be accessed (secure by default)
    // If element is shared, user must have a matching sharing organization
    return elementOrganizations.some((r) => userOrganizations.includes(r));
  }
  return true;
};

/**
 * Organization unrestricted mean that this element is visible whatever the organization the user belongs to.
 * @param element
 */
export const isOrganizationUnrestricted = (element: BasicStoreCommon) => {
  const types = [element.entity_type, ...getParentTypes(element.entity_type)];
  if (STIX_ORGANIZATIONS_UNRESTRICTED.some((r) => types.includes(r))) {
    return true;
  }
  return false;
};

export const isMarkingAllowed = (element: BasicStoreCommon, userAuthorizedMarkings: string[]) => {
  const elementMarkings = element[RELATION_OBJECT_MARKING] ?? [];
  if (elementMarkings.length > 0) {
    return elementMarkings.every((m) => userAuthorizedMarkings.includes(m));
  }
  return true;
};

export const canRequestAccess = async (context: AuthContext, user: AuthUser, elements: Array<BasicStoreCommon>) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  const elementsThatRequiresAccess: Array<BasicStoreCommon> = [];
  for (let i = 0; i < elements.length; i += 1) {
    if (!isOrganizationAllowed(elements[i], user, settings)) {
      elementsThatRequiresAccess.push(elements[i]);
    }
    // TODO before removing ORGA_SHARING_REQUEST_FF: When it's ready check Authorized members
  }
  return elementsThatRequiresAccess;
};

export const userFilterStoreElements = async (context: AuthContext, user: AuthUser, elements: Array<BasicStoreCommon>) => {
  const userFilterStoreElementsFn = async () => {
    // If user have bypass, grant access to all
    if (isBypassUser(user)) {
      return elements;
    }
    // If not filter by the inner markings
    const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
    const authorizedMarkings = user.allowed_marking.map((a) => a.internal_id);
    return elements.filter((element) => {
      // 1. Check markings
      if (!isMarkingAllowed(element, authorizedMarkings)) {
        return false;
      }
      // 2. Check organizations
      // Allow unrestricted entities
      if (isOrganizationUnrestricted(element)) {
        return true;
      }
      // Check restricted elements
      return isOrganizationAllowed(element, user, settings);
    });
  };
  return telemetry(context, user, 'FILTERING store filter', {
    [SEMATTRS_DB_NAME]: 'search_engine',
    [SEMATTRS_DB_OPERATION]: 'read',
  }, userFilterStoreElementsFn);
};

export const isUserCanAccessStoreElement = async (context: AuthContext, user: AuthUser, element: BasicStoreCommon) => {
  const elements = await userFilterStoreElements(context, user, [element]);
  return elements.length === 1;
};

export const isUserCanAccessStixElement = async (context: AuthContext, user: AuthUser, instance: StixObject) => {
  // If user have bypass, grant access to all
  if (isBypassUser(user)) {
    return true;
  }
  // 1. Check markings
  const instanceMarkings = instance.object_marking_refs ?? [];
  if (instanceMarkings.length > 0) {
    const userMarkings = (user.allowed_marking || []).map((m) => m.standard_id);
    const isUserHaveAccess = instanceMarkings.every((m) => userMarkings.includes(m));
    if (!isUserHaveAccess) {
      return false;
    }
  }
  // 2. Check organizations
  // Allow unrestricted entities
  const entityType = instance.extensions?.[STIX_EXT_OCTI]?.type ?? generateInternalType(instance);
  const types = [entityType, ...getParentTypes(entityType)];
  if (STIX_ORGANIZATIONS_UNRESTRICTED.some((r) => types.includes(r))) {
    return true;
  }
  // Check restricted elements
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  const elementOrganizations = instance.extensions?.[STIX_EXT_OCTI]?.granted_refs ?? [];
  const userOrganizations = user.allowed_organizations.map((o) => o.standard_id);
  // If platform organization is set
  if (settings.platform_organization) {
    // If user part of platform organization, is granted by default
    if (user.inside_platform_organization) {
      return true;
    }
    // If not, user is by design inside an organization
    // If element has no current sharing organization, it can be accessed (secure by default)
    // If element is shared, user must have a matching sharing organization
    return elementOrganizations.some((r) => userOrganizations.includes(r));
  }
  // If no platform organization is set, user can access
  return true;
};

// region member access

// returns all user member access ids : his id, his organizations ids (and parent organizations), his groups ids
export const computeUserMemberAccessIds = (user: AuthUser) => {
  const memberAccessIds = [user.id];
  if (user.allowed_organizations) {
    const userOrganizationsIds = user.allowed_organizations.map((org) => org.internal_id);
    memberAccessIds.push(...userOrganizationsIds);
  }
  if (user.groups) {
    const userGroupsIds = user.groups.map((group) => group.internal_id);
    memberAccessIds.push(...userGroupsIds);
  }
  if (user.roles) {
    const userRolesIds = user.roles.map((role) => role.internal_id);
    memberAccessIds.push(...userRolesIds);
  }
  return memberAccessIds;
};

// user access methods
export const isDirectAdministrator = (user: AuthUser, element: any) => {
  const elementAccessIds = element.authorized_members
    .filter((u: AuthorizedMember) => u.access_right === MEMBER_ACCESS_RIGHT_ADMIN)
    .map((u: AuthorizedMember) => u.id);
  const userMemberAccessIds = computeUserMemberAccessIds(user);
  return elementAccessIds.some((a: string) => userMemberAccessIds.includes(a));
};
export const getUserAccessRight = (user: AuthUser, element: any) => {
  if (!element.authorized_members || element.authorized_members.length === 0) { // no restricted user access on element
    return MEMBER_ACCESS_RIGHT_ADMIN;
  }
  const accessMembers = [...element.authorized_members];
  const userMemberAccessIds = computeUserMemberAccessIds(user);
  const foundAccessMembers = accessMembers.filter((u) => u.id === MEMBER_ACCESS_ALL || userMemberAccessIds.includes(u.id));
  // If user have extended capabilities, is an admin
  if ((element.authorized_authorities ?? []).some((c: string) => userMemberAccessIds.includes(c) || isUserHasCapability(user, c))) {
    return MEMBER_ACCESS_RIGHT_ADMIN;
  }
  // if user is bypass, user has admin access (needed for data management usage)
  if (isBypassUser(user)) {
    return MEMBER_ACCESS_RIGHT_ADMIN;
  }
  if (!foundAccessMembers.length) { // user has no access
    return null;
  }
  if (foundAccessMembers.some((m) => m.access_right === MEMBER_ACCESS_RIGHT_ADMIN)) {
    return MEMBER_ACCESS_RIGHT_ADMIN;
  }
  if (foundAccessMembers.some((m) => m.access_right === MEMBER_ACCESS_RIGHT_EDIT)) {
    return MEMBER_ACCESS_RIGHT_EDIT;
  }
  return MEMBER_ACCESS_RIGHT_VIEW;
};

// ensure that user can access the element (operation: edit / delete / manage-access)
export const validateUserAccessOperation = (user: AuthUser, element: any, operation: 'edit' | 'delete' | 'manage-access' | 'manage-authorities-access') => {
  if (isInternalObject(element.entity_type) && isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    return true;
  }
  if (isStixObject(element.entity_type)
    && operation === 'manage-access'
    && !isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS)
  ) {
    return false;
  }
  if (operation === 'manage-authorities-access'
    && !isUserHasCapability(user, SETTINGS_SET_ACCESSES)
  ) {
    return false;
  }
  const userAccessRight = getUserAccessRight(user, element);
  if (!userAccessRight) { // user has no access
    return false;
  }
  if (operation === 'edit') {
    return userAccessRight === MEMBER_ACCESS_RIGHT_EDIT || userAccessRight === MEMBER_ACCESS_RIGHT_ADMIN;
  }
  if (operation === 'delete' || operation === 'manage-access') {
    return userAccessRight === MEMBER_ACCESS_RIGHT_ADMIN;
  }
  return true;
};

export const isValidMemberAccessRight = (accessRight: string) => {
  return accessRight && MEMBER_ACCESS_RIGHTS.includes(accessRight);
};

export const controlUserRestrictDeleteAgainstElement = <T extends ObjectWithCreators>(user: AuthUser, existingElement: T, noThrow = false) => {
  const hasCreatorIdAttribute = schemaAttributesDefinition.getAttribute(existingElement.entity_type, 'creator_id');
  if (!hasCreatorIdAttribute) {
    return true; // no creator to check, it's ok
  }
  if (user.restrict_delete && isNotEmptyField(existingElement.creator_id as string[]) && existingElement.creator_id !== user.id && !existingElement.creator_id?.includes(user.id)) {
    if (noThrow) {
      return false;
    }
    throw FunctionalError('Restricted to delete this element (not the technical creator)', { user_id: user.id, element_id: existingElement.id });
  }
  return true;
};
