import * as R from 'ramda';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import type { Context, Span, Tracer } from '@opentelemetry/api';
import { context as telemetryContext, trace } from '@opentelemetry/api';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreCommon, BasicStoreSettings } from '../types/store';
import type { StixCoreObject } from '../types/stix-common';
import { STIX_ORGANIZATIONS_UNRESTRICTED } from '../schema/stixDomainObject';
import { generateInternalType, getParentTypes } from '../schema/schemaUtils';
import { telemetry } from '../config/tracing';

export const BYPASS = 'BYPASS';
export const BYPASS_REFERENCE = 'BYPASSREFERENCE';
export const SETTINGS_SET_ACCESSES = 'SETTINGS_SETACCESSES';
export const TAXIIAPI_SETCOLLECTIONS = 'TAXIIAPI_SETCOLLECTIONS';
export const KNOWLEDGE_ORGANIZATION_RESTRICT = 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT';

export const ROLE_ADMINISTRATOR = 'Administrator';
const RETENTION_MANAGER_USER_UUID = '82ed2c6c-eb27-498e-b904-4f2abc04e05f';
export const RULE_MANAGER_USER_UUID = 'f9d7b43f-b208-4c56-8637-375a1ce84943';
export const REDACTED_USER_UUID = '31afac4e-6b99-44a0-b91b-e04738d31461';

export const MEMBER_ACCESS_ALL = 'ALL';
export const MEMBER_ACCESS_RIGHT_ADMIN = 'admin';
export const MEMBER_ACCESS_RIGHT_EDIT = 'edit';
export const MEMBER_ACCESS_RIGHT_VIEW = 'view';
const MEMBER_ACCESS_RIGHTS = [MEMBER_ACCESS_RIGHT_VIEW, MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_ADMIN];

export const SYSTEM_USER: AuthUser = {
  entity_type: 'User',
  id: OPENCTI_SYSTEM_UUID,
  internal_id: OPENCTI_SYSTEM_UUID,
  individual_id: undefined,
  name: 'SYSTEM',
  user_email: 'SYSTEM',
  inside_platform_organization: true,
  origin: { user_id: OPENCTI_SYSTEM_UUID },
  roles: [{ name: ROLE_ADMINISTRATOR }],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  default_marking: [],
  all_marking: [],
  api_token: '',
};

export const RETENTION_MANAGER_USER: AuthUser = {
  entity_type: 'User',
  id: RETENTION_MANAGER_USER_UUID,
  internal_id: RETENTION_MANAGER_USER_UUID,
  individual_id: undefined,
  name: 'RETENTION MANAGER',
  user_email: 'RETENTION MANAGER',
  inside_platform_organization: true,
  origin: { user_id: RETENTION_MANAGER_USER_UUID },
  roles: [{ name: ROLE_ADMINISTRATOR }],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  default_marking: [],
  all_marking: [],
  api_token: '',
};

export const RULE_MANAGER_USER: AuthUser = {
  entity_type: 'User',
  id: RULE_MANAGER_USER_UUID,
  internal_id: RULE_MANAGER_USER_UUID,
  individual_id: undefined,
  name: 'RULE MANAGER',
  user_email: 'RULE MANAGER',
  inside_platform_organization: true,
  origin: { user_id: RULE_MANAGER_USER_UUID },
  roles: [{ name: ROLE_ADMINISTRATOR }],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  default_marking: [],
  all_marking: [],
  api_token: '',
};

export const REDACTED_USER: AuthUser = {
  entity_type: 'User',
  id: REDACTED_USER_UUID,
  internal_id: REDACTED_USER_UUID,
  individual_id: undefined,
  name: '*** Redacted ***',
  user_email: '*** Redacted ***',
  inside_platform_organization: false,
  origin: { user_id: REDACTED_USER_UUID },
  roles: [],
  groups: [],
  capabilities: [],
  organizations: [],
  allowed_organizations: [],
  allowed_marking: [],
  default_marking: [],
  all_marking: [],
  api_token: '',
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
  [REDACTED_USER.id]: REDACTED_USER
};

export const isBypassUser = (user: AuthUser): boolean => {
  return R.find((s) => s.name === BYPASS, user.capabilities || []) !== undefined;
};

export const isUserHasCapability = (user: AuthUser, capability: string): boolean => {
  return isBypassUser(user) || R.find((s) => s.name === capability, user.capabilities || []) !== undefined;
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
      const elementMarkings = element[RELATION_OBJECT_MARKING] ?? [];
      if (elementMarkings.length > 0) {
        const markingAllowed = elementMarkings.every((m) => authorizedMarkings.includes(m));
        if (!markingAllowed) {
          return false;
        }
      }
      // 2. Check organizations
      // Allow unrestricted entities
      const types = [element.entity_type, ...getParentTypes(element.entity_type)];
      if (STIX_ORGANIZATIONS_UNRESTRICTED.some((r) => types.includes(r))) {
        return true;
      }
      // Check restricted elements
      const elementOrganizations = element[RELATION_GRANTED_TO] ?? [];
      const userOrganizations = user.allowed_organizations.map((o) => o.internal_id);
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
      // If no platform organization is set, user can access empty sharing and dedicated sharing
      return elementOrganizations.length === 0 || elementOrganizations.some((r) => userOrganizations.includes(r));
    });
  };
  return telemetry(context, user, 'FILTERING store filter', {
    [SemanticAttributes.DB_NAME]: 'search_engine',
    [SemanticAttributes.DB_OPERATION]: 'read',
  }, userFilterStoreElementsFn);
};

export const isUserCanAccessStoreElement = async (context: AuthContext, user: AuthUser, element: BasicStoreCommon) => {
  const elements = await userFilterStoreElements(context, user, [element]);
  return elements.length === 1;
};

export const isUserCanAccessStixElement = async (context: AuthContext, user: AuthUser, instance: StixCoreObject) => {
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
  // If no platform organization is set, user can access empty sharing and dedicated sharing
  return elementOrganizations.length === 0 || elementOrganizations.some((r) => userOrganizations.includes(r));
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
  return memberAccessIds;
};

// user access methods
export const getUserAccessRight = (user: AuthUser, element: any) => {
  if (!element.authorized_members) { // no restricted user access on element
    return MEMBER_ACCESS_RIGHT_ADMIN;
  }
  const accessMembers = [...element.authorized_members];
  const userMemberAccessIds = computeUserMemberAccessIds(user);
  const foundAccessMembers = accessMembers.filter((u) => u.id === MEMBER_ACCESS_ALL || userMemberAccessIds.includes(u.id));
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
export const validateUserAccessOperation = (user: AuthUser, element: any, operation: 'edit' | 'delete' | 'manage-access') => {
  if (isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    return true;
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
