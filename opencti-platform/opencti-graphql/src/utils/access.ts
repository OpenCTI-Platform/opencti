import * as R from 'ramda';
import type { Context, Span, Tracer } from '@opentelemetry/api';
import { context as telemetryContext, trace } from '@opentelemetry/api';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreCommon, BasicStoreSettings } from '../types/store';
import type { StixCoreObject } from '../types/stix-common';
import { STIX_ORGANIZATIONS_UNRESTRICTED } from '../schema/stixDomainObject';
import { getParentTypes } from '../schema/schemaUtils';

export const BYPASS = 'BYPASS';
export const BYPASS_REFERENCE = 'BYPASSREFERENCE';
export const SETTINGS_SET_ACCESSES = 'SETTINGS_SETACCESSES';
export const KNOWLEDGE_ORGANIZATION_RESTRICT = 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT';
export const ROLE_ADMINISTRATOR = 'Administrator';
const RETENTION_MANAGER_USER_UUID = '82ed2c6c-eb27-498e-b904-4f2abc04e05f';
export const RULE_MANAGER_USER_UUID = 'f9d7b43f-b208-4c56-8637-375a1ce84943';

export const SYSTEM_USER: AuthUser = {
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
  all_marking: [],
  api_token: '',
};

export const RETENTION_MANAGER_USER: AuthUser = {
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
  all_marking: [],
  api_token: '',
};

export const RULE_MANAGER_USER: AuthUser = {
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
  all_marking: [],
  api_token: '',
};

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
  [RULE_MANAGER_USER.id]: RULE_MANAGER_USER
};

export const isBypassUser = (user: AuthUser): boolean => {
  return R.find((s) => s.name === BYPASS, user.capabilities || []) !== undefined;
};

export const isUserHasCapability = (user: AuthUser, capability: string): boolean => {
  return isBypassUser(user) || R.find((s) => s.name === capability, user.capabilities || []) !== undefined;
};

export const userFilterStoreElements = async (context: AuthContext, user: AuthUser, elements: Array<BasicStoreCommon>) => {
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
  const entityType = instance.extensions[STIX_EXT_OCTI].type;
  const types = [entityType, ...getParentTypes(entityType)];
  if (STIX_ORGANIZATIONS_UNRESTRICTED.some((r) => types.includes(r))) {
    return true;
  }
  // Check restricted elements
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  const elementOrganizations = instance.extensions[STIX_EXT_OCTI].granted_refs ?? [];
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
