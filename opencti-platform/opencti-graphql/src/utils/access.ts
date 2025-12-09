import type { Context, Span, Tracer } from '@opentelemetry/api';
import { context as telemetryContext, trace } from '@opentelemetry/api';
import { SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { ACCOUNT_STATUS_ACTIVE, isFeatureEnabled } from '../config/conf';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { telemetry } from '../config/tracing';
import { getEntitiesMapFromCache, getEntityFromCache } from '../database/cache';
import { extractIdsFromStoreObject, isNotEmptyField, REDACTED_INFORMATION, RESTRICTED_INFORMATION } from '../database/utils';
import { type Creator, type FilterGroup, FilterMode, type Participant } from '../generated/graphql';
import type { BasicStoreEntityDraftWorkspace } from '../modules/draftWorkspace/draftWorkspace-types';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER, isInternalObject } from '../schema/internalObject';
import { RELATION_PARTICIPATE_TO } from '../schema/internalRelationship';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { generateInternalType, getParentTypes } from '../schema/schemaUtils';
import { isStixObject } from '../schema/stixCoreObject';
import { STIX_ORGANIZATIONS_UNRESTRICTED } from '../schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import type { UpdateEvent } from '../types/event';
import type { BasicStoreSettings } from '../types/settings';
import type { StixObject } from '../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import type { BasicStoreCommon } from '../types/store';
import type { AuthContext, AuthUser, UserRole } from '../types/user';

export const DEFAULT_INVALID_CONF_VALUE = 'ChangeMe';

export const BYPASS = 'BYPASS';
export const KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE = 'KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE';
export const KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS = 'KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS';
export const SETTINGS_SET_ACCESSES = 'SETTINGS_SETACCESSES';
export const SETTINGS_SETPARAMETERS = 'SETTINGS_SETPARAMETERS';
export const SETTINGS_SETMANAGEXTMHUB = 'SETTINGS_SETMANAGEXTMHUB';
export const SETTINGS_SUPPORT = 'SETTINGS_SUPPORT';
export const TAXIIAPI_SETCOLLECTIONS = 'TAXIIAPI_SETCOLLECTIONS';
export const INGESTION_SETINGESTIONS = 'INGESTION_SETINGESTIONS';
export const CSVMAPPERS = 'CSVMAPPERS';
export const KNOWLEDGE = 'KNOWLEDGE';
export const KNOWLEDGE_KNPARTICIPATE = 'KNOWLEDGE_KNPARTICIPATE';
export const KNOWLEDGE_KNUPDATE = 'KNOWLEDGE_KNUPDATE';
export const KNOWLEDGE_ORGANIZATION_RESTRICT = 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT';
export const KNOWLEDGE_KNUPDATE_KNDELETE = 'KNOWLEDGE_KNUPDATE_KNDELETE';
export const KNOWLEDGE_KNUPDATE_KNMERGE = 'KNOWLEDGE_KNUPDATE_KNMERGE';
export const KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS = 'KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS';
export const KNOWLEDGE_KNUPLOAD = 'KNOWLEDGE_KNUPLOAD';
export const KNOWLEDGE_KNASKIMPORT = 'KNOWLEDGE_KNASKIMPORT';
export const KNOWLEDGE_KNENRICHMENT = 'KNOWLEDGE_KNENRICHMENT';
export const KNOWLEDGE_KNDISSEMINATION = 'KNOWLEDGE_KNDISSEMINATION';
export const VIRTUAL_ORGANIZATION_ADMIN = 'VIRTUAL_ORGANIZATION_ADMIN';
export const SETTINGS_SETACCESSES = 'SETTINGS_SETACCESSES';
export const SETTINGS_SECURITYACTIVITY = 'SETTINGS_SECURITYACTIVITY';
export const SETTINGS_SETCUSTOMIZATION = 'SETTINGS_SETCUSTOMIZATION';
export const SETTINGS_SETLABELS = 'SETTINGS_SETLABELS';
export const PIRAPI = 'PIRAPI';
export const AUTOMATION = 'AUTOMATION';
export const AUTOMATION_AUTMANAGE = 'AUTOMATION_AUTMANAGE';

export const CONTAINER_SHARING_USER_UUID = 'cc3aef5c-6f05-434b-8bdf-8d370046f017';
export const ROLE_DEFAULT = 'Default';
export const ROLE_ADMINISTRATOR = 'Administrator';
const RETENTION_MANAGER_USER_UUID = '82ed2c6c-eb27-498e-b904-4f2abc04e05f';
export const EXPIRATION_MANAGER_USER_UUID = '21763151-f598-4f49-97c5-9051b2d25a5c';
export const RULE_MANAGER_USER_UUID = 'f9d7b43f-b208-4c56-8637-375a1ce84943';
export const AUTOMATION_MANAGER_USER_UUID = 'c49fe040-2dad-412d-af07-ce639204ad55';
export const DECAY_MANAGER_USER_UUID = '7f176d74-9084-4d23-8138-22ac78549547';
export const GARBAGE_COLLECTION_MANAGER_USER_UUID = 'c30d12be-d5fb-4724-88e7-8a7c9a4516c2';
const TELEMETRY_MANAGER_USER_UUID = 'c30d12be-d5fb-4724-88e7-8a7c9a4516c3';
export const REDACTED_USER_UUID = '31afac4e-6b99-44a0-b91b-e04738d31461';
export const RESTRICTED_USER_UUID = '27d2b0af-4d1e-42ae-a50c-9691bf57f35d';
const PIR_MANAGER_USER_UUID = '1e20b6e5-e0f7-46f2-bacb-c37e4f8707a2';
const HUB_REGISTRATION_MANAGER_USER_UUID = 'e16d7175-17c7-4dae-bd3c-48c939f47dfb';

export enum AccessOperation {
  EDIT = 'edit',
  DELETE = 'delete',
  MANAGE_ACCESS = 'manage-access',
  MANAGE_AUTHORITIES_ACCESS = 'manage-authorities-access',
}

export const MEMBER_ACCESS_ALL = 'ALL';
export const MEMBER_ACCESS_CREATOR = 'CREATOR';
export const MEMBER_ACCESS_RIGHT_ADMIN = 'admin';
export const MEMBER_ACCESS_RIGHT_EDIT = 'edit';
export const MEMBER_ACCESS_RIGHT_USE = 'use';
export const MEMBER_ACCESS_RIGHT_VIEW = 'view';
let MEMBER_ACCESS_RIGHTS = [MEMBER_ACCESS_RIGHT_VIEW, MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_ADMIN];
if (isFeatureEnabled('ACCESS_RESTRICTION_CAN_USE')) {
  MEMBER_ACCESS_RIGHTS = [MEMBER_ACCESS_RIGHT_VIEW, MEMBER_ACCESS_RIGHT_USE, MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_ADMIN];
}

type ObjectWithCreators = {
  id: string;
  entity_type: string;
  creator_id?: string | string[] | undefined;
};

const administratorRoleId = uuidv4();
export const ADMINISTRATOR_ROLE: UserRole = {
  id: administratorRoleId,
  entity_type: 'Role',
  internal_id: administratorRoleId,
  name: ROLE_ADMINISTRATOR,
};

const defaultRoleId = uuidv4();
export const DEFAULT_ROLE: UserRole = {
  id: defaultRoleId,
  entity_type: 'Role',
  internal_id: defaultRoleId,
  name: ROLE_DEFAULT,
};

export const SYSTEM_USER: AuthUser = {
  entity_type: 'User',
  id: OPENCTI_SYSTEM_UUID,
  internal_id: OPENCTI_SYSTEM_UUID,
  individual_id: undefined,
  name: 'SYSTEM',
  user_email: 'SYSTEM',
  origin: { user_id: OPENCTI_SYSTEM_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_marking: [],
  default_marking: [],
  max_shareable_marking: [],
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

export const CONTAINER_SHARING_USER: AuthUser = {
  entity_type: 'User',
  id: CONTAINER_SHARING_USER_UUID,
  internal_id: CONTAINER_SHARING_USER_UUID,
  individual_id: undefined,
  name: 'CONTAINER SHARING',
  user_email: 'CONTAINER SHARING',
  origin: { user_id: CONTAINER_SHARING_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_marking: [],
  default_marking: [],
  max_shareable_marking: [],
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
  origin: { user_id: RETENTION_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
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
  origin: { user_id: RULE_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
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
  origin: { user_id: AUTOMATION_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
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
  origin: { user_id: DECAY_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
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
  origin: { user_id: GARBAGE_COLLECTION_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
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
  name: REDACTED_INFORMATION,
  user_email: REDACTED_INFORMATION,
  origin: { user_id: REDACTED_USER_UUID, socket: 'internal' },
  roles: [],
  groups: [],
  capabilities: [],
  organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
  api_token: '',
  account_lock_after_date: undefined,
  account_status: ACCOUNT_STATUS_ACTIVE,
  effective_confidence_level: null,
  user_confidence_level: null,
  no_creators: false,
  restrict_delete: false,
};

export const RESTRICTED_USER: AuthUser = {
  administrated_organizations: [],
  entity_type: 'User',
  id: RESTRICTED_USER_UUID,
  internal_id: RESTRICTED_USER_UUID,
  individual_id: undefined,
  name: RESTRICTED_INFORMATION,
  user_email: RESTRICTED_INFORMATION,
  origin: { user_id: RESTRICTED_USER_UUID, socket: 'internal' },
  roles: [],
  groups: [],
  capabilities: [],
  organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
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
  origin: { user_id: TELEMETRY_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
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

export const EXPIRATION_MANAGER_USER: AuthUser = {
  entity_type: 'User',
  id: EXPIRATION_MANAGER_USER_UUID,
  internal_id: EXPIRATION_MANAGER_USER_UUID,
  individual_id: undefined,
  name: 'EXPIRATION MANAGER',
  user_email: 'EXPIRATION MANAGER',
  origin: { user_id: EXPIRATION_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
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

export const PIR_MANAGER_USER: AuthUser = {
  entity_type: 'User',
  id: PIR_MANAGER_USER_UUID,
  internal_id: PIR_MANAGER_USER_UUID,
  individual_id: undefined,
  name: 'PIR MANAGER',
  user_email: 'PIR MANAGER',
  origin: { user_id: PIR_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
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

export const HUB_REGISTRATION_MANAGER_USER: AuthUser = {
  entity_type: 'User',
  id: HUB_REGISTRATION_MANAGER_USER_UUID,
  internal_id: HUB_REGISTRATION_MANAGER_USER_UUID,
  individual_id: undefined,
  name: 'HUB REGISTRATION MANAGER',
  user_email: 'HUB REGISTRATION MANAGER',
  origin: { user_id: HUB_REGISTRATION_MANAGER_USER_UUID, socket: 'internal' },
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  organizations: [],
  allowed_marking: [],
  max_shareable_marking: [],
  default_marking: [],
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

export interface AuthorizedMember { id: string; access_right: string; groups_restriction_ids?: string[] | null }

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

export const enforceEnableFeatureFlag = (flag: string) => {
  if (!isFeatureEnabled(flag)) {
    throw UnsupportedError('Feature is disabled', { flag });
  }
};

export const executionContext = (source: string, auth?: AuthUser, draftContext?: string): AuthContext => {
  const tracer = trace.getTracer('instrumentation-opencti', '1.0.0');
  const tracing = new TracingContext(tracer);
  return {
    otp_mandatory: false,
    user_inside_platform_organization: false,
    source,
    tracing,
    user: auth ?? undefined,
    draft_context: draftContext ?? undefined,
  };
};

export const INTERNAL_USERS = {
  [SYSTEM_USER.id]: SYSTEM_USER,
  [CONTAINER_SHARING_USER.id]: CONTAINER_SHARING_USER,
  [RETENTION_MANAGER_USER.id]: RETENTION_MANAGER_USER,
  [RULE_MANAGER_USER.id]: RULE_MANAGER_USER,
  [AUTOMATION_MANAGER_USER.id]: AUTOMATION_MANAGER_USER,
  [DECAY_MANAGER_USER.id]: DECAY_MANAGER_USER,
  [EXPIRATION_MANAGER_USER.id]: EXPIRATION_MANAGER_USER,
  [REDACTED_USER.id]: REDACTED_USER,
  [RESTRICTED_USER.id]: RESTRICTED_USER,
  [PIR_MANAGER_USER.id]: PIR_MANAGER_USER,
  [HUB_REGISTRATION_MANAGER_USER.id]: HUB_REGISTRATION_MANAGER_USER,
};

export const INTERNAL_USERS_WITHOUT_REDACTED = {
  [SYSTEM_USER.id]: SYSTEM_USER,
  [CONTAINER_SHARING_USER.id]: CONTAINER_SHARING_USER,
  [RETENTION_MANAGER_USER.id]: RETENTION_MANAGER_USER,
  [RULE_MANAGER_USER.id]: RULE_MANAGER_USER,
  [AUTOMATION_MANAGER_USER.id]: AUTOMATION_MANAGER_USER,
  [EXPIRATION_MANAGER_USER.id]: EXPIRATION_MANAGER_USER,
  [DECAY_MANAGER_USER.id]: DECAY_MANAGER_USER,
  [PIR_MANAGER_USER.id]: PIR_MANAGER_USER,
  [HUB_REGISTRATION_MANAGER_USER.id]: HUB_REGISTRATION_MANAGER_USER,
};

export const isInternalUser = (user: AuthUser): boolean => {
  return INTERNAL_USERS[user.id] !== undefined;
};

export const isBypassUser = (user: AuthUser): boolean => {
  return R.find((s) => s.name === BYPASS, user.capabilities || []) !== undefined;
};

export const isServiceAccountUser = (user: AuthUser): boolean => {
  return user.user_service_account === true;
};

export const isUserHasCapability = (user: AuthUser, capability: string): boolean => {
  const isInDraftContext = !!user.draft_context;
  const isIncludedInCapabilities = (user.capabilities || []).some((s) => capability !== BYPASS && s.name.includes(capability));
  const isIncludedInDraftCapabilities = (user.capabilitiesInDraft || []).some((s) => s.name.includes(capability));

  return isBypassUser(user) || isIncludedInCapabilities || (isInDraftContext && isIncludedInDraftCapabilities);
};

export const isUserHasCapabilities = (user: AuthUser, capabilities: string[] = []) => {
  return capabilities.every((capability) => isUserHasCapability(user, capability));
};

export const isOnlyOrgaAdmin = (user: AuthUser) => {
  return !isUserHasCapability(user, SETTINGS_SET_ACCESSES) && isUserHasCapability(user, VIRTUAL_ORGANIZATION_ADMIN);
};

// returns all user member access ids : his id, his organizations ids (and parent organizations), his groups ids
export const computeUserMemberAccessIds = (user: AuthUser) => {
  const memberAccessIds = [user.id];
  if (user.organizations) {
    const userOrganizationsIds = user.organizations.map((org) => org.internal_id);
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

// region entity access by user
export const getExplicitUserAccessRight = (user: AuthUser, element: { restricted_members?: AuthorizedMember[]; authorized_authorities?: string[] }) => {
  const userMemberAccessIds = computeUserMemberAccessIds(user);
  const userGroupsIds = user.groups.map((group) => group.internal_id);
  const foundAccessMembers = (element.restricted_members ?? []).filter((u) => (u.id === MEMBER_ACCESS_ALL || userMemberAccessIds.includes(u.id))
    && (!u.groups_restriction_ids || u.groups_restriction_ids.length === 0 || u.groups_restriction_ids.every((g) => userGroupsIds.includes(g))));
  if (!foundAccessMembers.length) { // user has no access
    return null;
  }
  if (foundAccessMembers.some((m) => m.access_right === MEMBER_ACCESS_RIGHT_ADMIN)) {
    return MEMBER_ACCESS_RIGHT_ADMIN;
  }
  if (foundAccessMembers.some((m) => m.access_right === MEMBER_ACCESS_RIGHT_EDIT)) {
    return MEMBER_ACCESS_RIGHT_EDIT;
  }
  if (foundAccessMembers.some((m) => m.access_right === MEMBER_ACCESS_RIGHT_USE)) {
    return MEMBER_ACCESS_RIGHT_USE;
  }
  return MEMBER_ACCESS_RIGHT_VIEW;
};

export const getUserAccessRight = (user: AuthUser, element: { restricted_members?: AuthorizedMember[]; authorized_authorities?: string[] }) => {
  // if user is bypass, user has admin access (needed for data management usage)
  if (isBypassUser(user)) {
    return MEMBER_ACCESS_RIGHT_ADMIN;
  }
  // no restricted user access on element
  if (!element.restricted_members || element.restricted_members.length === 0) {
    return MEMBER_ACCESS_RIGHT_ADMIN;
  }
  // If user have authorities, is an admin
  const userMemberAccessIds = computeUserMemberAccessIds(user);
  if ((element.authorized_authorities ?? []).some((c: string) => userMemberAccessIds.includes(c) || isUserHasCapability(user, c))) {
    return MEMBER_ACCESS_RIGHT_ADMIN;
  }

  if (isServiceAccountUser(user)) {
    return MEMBER_ACCESS_RIGHT_EDIT;
  }

  return getExplicitUserAccessRight(user, element);
};

export const hasAuthorizedMemberAccess = (user: AuthUser, element: { restricted_members?: AuthorizedMember[]; authorized_authorities?: string[] }) => {
  const userAccessRight = getUserAccessRight(user, element);
  return !!userAccessRight;
};

export const isUserInAuthorizedMember = (user: AuthUser, element: { restricted_members?: AuthorizedMember[]; authorized_authorities?: string[] }) => {
  const userAccessRight = getExplicitUserAccessRight(user, element);
  return !!userAccessRight;
};

const isEntityOrganizationsAllowed = (
  context: AuthContext,
  entityInternalId: string,
  entityOrganizations: string[],
  user: AuthUser,
  hasPlatformOrg: boolean,
) => {
  // If platform organization is set
  if (hasPlatformOrg) {
    const userOrganizations = user.organizations.map((o) => extractIdsFromStoreObject(o)).flat();

    // If user part of platform organization, is granted by default
    if (context.user_inside_platform_organization) {
      return true;
    }
    // Grant access to the user individual
    if (entityInternalId === user.individual_id) {
      return true;
    }
    // If not, user is by design inside an organization
    // If element has no current sharing organization, it can be accessed (secure by default)
    // If element is shared, user must have a matching sharing organization
    return entityOrganizations.some((r) => userOrganizations.includes(r));
  }
  return true;
};

export const isOrganizationAllowed = (context: AuthContext, element: BasicStoreCommon, user: AuthUser, hasPlatformOrg: boolean) => {
  const elementOrganizations = element[RELATION_GRANTED_TO] ?? [];
  return isEntityOrganizationsAllowed(context, element.internal_id, elementOrganizations, user, hasPlatformOrg);
};

const isOrganizationUnrestrictedForEntityType = (entityType: string) => {
  const types = [entityType, ...getParentTypes(entityType)];
  if (STIX_ORGANIZATIONS_UNRESTRICTED.some((r) => types.includes(r))) {
    return true;
  }
  return false;
};
/**
 * Organization unrestricted mean that this element is visible whatever the organization the user belongs to.
 * @param element
 */
export const isOrganizationUnrestricted = (element: BasicStoreCommon) => {
  return isOrganizationUnrestrictedForEntityType(element.entity_type);
};

export const isMarkingAllowed = (element: BasicStoreCommon, userAuthorizedMarkings: string[]) => {
  const elementMarkings = element[RELATION_OBJECT_MARKING] ?? [];
  if (elementMarkings.length > 0) {
    return elementMarkings.every((m) => userAuthorizedMarkings.includes(m));
  }
  return true;
};

export const checkUserFilterStoreElements = (
  context: AuthContext,
  user: AuthUser,
  element: BasicStoreCommon,
  authorizedMarkings: string[],
  hasPlatformOrg: boolean,
) => {
  // 1. Check markings
  if (!isMarkingAllowed(element, authorizedMarkings)) {
    return false;
  }
  // 2. check authorized members
  if (!hasAuthorizedMemberAccess(user, element)) {
    return false;
  }
  // 3. Check organizations
  // Allow unrestricted entities
  if (isOrganizationUnrestricted(element)) {
    return true;
  }
  // Check restricted elements
  // either allowed by orga sharing or has authorized members access if restricted_members are defined (bypass orga sharing)
  return isOrganizationAllowed(context, element, user, hasPlatformOrg)
    || (element.restricted_members && element.restricted_members.length > 0 && hasAuthorizedMemberAccess(user, element));
};

export const userFilterStoreElements = async (context: AuthContext, user: AuthUser, elements: Array<BasicStoreCommon>) => {
  const userFilterStoreElementsFn = async () => {
    // If user have bypass, grant access to all
    if (isBypassUser(user)) {
      return elements;
    }
    // If not filter by the inner markings
    const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
    const hasPlatformOrg = !!settings.platform_organization;
    const authorizedMarkings = user.allowed_marking.map((a) => a.internal_id);
    return elements.filter((element) => {
      return checkUserFilterStoreElements(context, user, element, authorizedMarkings, hasPlatformOrg);
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

export const checkUserCanAccessStixElement = (context: AuthContext, user: AuthUser, instance: StixObject, hasPlatformOrg: boolean) => {
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
  const restricted_members = instance.extensions?.[STIX_EXT_OCTI]?.authorized_members ?? [];
  const authorizedMemberAllowed = hasAuthorizedMemberAccess(user, { restricted_members });
  // 2. check authorized members
  if (!authorizedMemberAllowed) {
    return false;
  }
  // 3. Check organizations
  // Allow unrestricted entities
  const entityType = instance.extensions?.[STIX_EXT_OCTI]?.type ?? generateInternalType(instance);
  if (isOrganizationUnrestrictedForEntityType(entityType)) {
    return true;
  }
  // Check restricted elements
  const elementOrganizations = instance.extensions?.[STIX_EXT_OCTI]?.granted_refs ?? [];
  const organizationAllowed = isEntityOrganizationsAllowed(context, instance.id, elementOrganizations, user, hasPlatformOrg);
  // either allowed by organization or authorized members
  return organizationAllowed || (restricted_members.length > 0 && authorizedMemberAllowed);
};

export const isUserCanAccessStixElement = async (context: AuthContext, user: AuthUser, instance: StixObject) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  const hasPlatformOrg = !!settings.platform_organization;
  return checkUserCanAccessStixElement(context, user, instance, hasPlatformOrg);
};

const checkUserCanAccessMarkings = async (user: AuthUser, markingIds: string[]) => {
  if (markingIds.length === 0 || isBypassUser(user)) {
    return true;
  }
  const userMarkingIds = (user.allowed_marking || []).map((m) => m.internal_id);
  if (markingIds.every((m) => userMarkingIds.includes(m))) {
    return true;
  }
  return false;
};

export const isUserCanAccessStreamUpdateEvent = async (user: AuthUser, updateEvent: UpdateEvent) => {
  const relatedRestrictions = updateEvent.context.related_restrictions;
  if (!relatedRestrictions) {
    return true;
  }
  const markingsRestrictions = relatedRestrictions.markings ?? [];
  if (markingsRestrictions.length > 0) {
    return checkUserCanAccessMarkings(user, markingsRestrictions);
  }
  return true;
};
// end region

// region member access

// user access methods
export const isDirectAdministrator = (user: AuthUser, element: any) => {
  const elementAccessIds = element.restricted_members
    .filter((u: AuthorizedMember) => u.access_right === MEMBER_ACCESS_RIGHT_ADMIN)
    .map((u: AuthorizedMember) => u.id);
  const userMemberAccessIds = computeUserMemberAccessIds(user);
  return elementAccessIds.some((a: string) => userMemberAccessIds.includes(a));
};

const hasUserAccessToOperation = (
  user: AuthUser,
  element: { restricted_members?: AuthorizedMember[]; authorized_authorities?: string[] },
  operation: AccessOperation,
) => {
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

// Ensure that user can access the element (operation: edit / delete / manage-access)
export const validateUserAccessOperation = (user: AuthUser, element: any, operation: AccessOperation, draft?: BasicStoreEntityDraftWorkspace | null) => {
  // 1. Check draft authorized members permissions
  if (draft && !hasUserAccessToOperation(user, draft, operation)) {
    return false;
  }

  // 2. Internal objects management
  if (isInternalObject(element.entity_type) && isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    return true;
  }

  // 3. Specific STIX object management restrictions
  if (isStixObject(element.entity_type)
    && operation === 'manage-access'
    && !isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS)
  ) {
    return false;
  }

  // 4. General access management restrictions
  if (operation === 'manage-authorities-access'
    && !isUserHasCapability(user, SETTINGS_SET_ACCESSES)
  ) {
    return false;
  }

  // 5. Check access to the element (entity, container, etc.)
  return hasUserAccessToOperation(user, element, operation);
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

/**
 * Verify that the Entity in Marking is one of user allowed
 * @param context
 * @param user
 * @param markingId
 */
export const validateMarking = async (context: AuthContext, user: AuthUser, markingId: string) => {
  if (isBypassUser(user)) {
    return;
  }
  const markings = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const userMarking = (user.allowed_marking || []).map((m) => markings.get(m.internal_id)).filter((m) => isNotEmptyField(m)) as BasicStoreCommon[];
  const userMarkingIds = userMarking.map((marking) => extractIdsFromStoreObject(marking)).flat();
  if (!userMarkingIds.includes(markingId)) {
    throw FunctionalError('User trying to create the data has missing markings', { id: markingId, user_markings: userMarkingIds });
  }
};

export const isUserInPlatformOrganization = (user: AuthUser, settings: BasicStoreSettings) => {
  if (isBypassUser(user)) {
    return true;
  }
  if (user.user_service_account) {
    return true;
  }
  const userOrganizationIds = (user.organizations ?? []).map((organization) => organization.internal_id);
  return settings.platform_organization ? userOrganizationIds.includes(settings.platform_organization) : true;
};

type ParticipantWithOrgIds = Participant & Creator & {
  representative?: {
    main: string;
    secondary: string;
  };
  [RELATION_PARTICIPATE_TO]?: string[];
  user_service_account?: boolean;
};

export enum FilterMembersMode {
  RESTRICT = 'restrict',
  EXCLUDE = 'exclude',
}
export const filterMembersWithUsersOrgs = async (
  context: AuthContext,
  user: AuthUser,
  members: ParticipantWithOrgIds[],
  filterMode = FilterMembersMode.RESTRICT,
): Promise<ParticipantWithOrgIds[]> => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const userInPlatformOrg = isUserInPlatformOrganization(user, settings);
  if (!userInPlatformOrg) {
    const userOrgIds = (user.organizations || []).map((org) => org.id);
    const resultMembers = [];
    for (let i = 0; i < members.length; i += 1) {
      const member = members[i];
      if (member.id === user.id || INTERNAL_USERS[member.id] || member.user_service_account) {
        resultMembers.push(member);
      } else {
        const memberOrgIds = member[RELATION_PARTICIPATE_TO] ?? [];
        const sameOrg = memberOrgIds.some((id) => userOrgIds.includes(id));
        if (sameOrg) {
          resultMembers.push(member);
        } else {
          if (filterMode === FilterMembersMode.RESTRICT) {
            const restrictedMember = {
              ...member,
              name: RESTRICTED_USER.name,
              user_email: RESTRICTED_USER.user_email,
              representative: {
                main: RESTRICTED_USER.name,
                secondary: RESTRICTED_USER.name,
              },
            };
            resultMembers.push(restrictedMember);
          }
        }
      }
    }
    return resultMembers;
  }
  return members;
};

interface ListArgs {
  filters?: FilterGroup;
  entityTypes?: string[] | null;
  [key: string]: any;
}

export const applyOrganizationRestriction = async (
  context: AuthContext,
  user: AuthUser,
  args: ListArgs,
) => {
  const { filters: argsFilters } = args;
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const userInPlatformOrg = isUserInPlatformOrganization(user, settings);

  if (!userInPlatformOrg) {
    const userOrgIds = (user.organizations || []).map((org) => org.id);
    const membersFilters = {
      key: ['participate-to'],
      values: userOrgIds,
      operator: 'eq',
    };
    const userTypeFilters = {
      key: ['entity_type'],
      values: [ENTITY_TYPE_USER],
      operator: 'not_eq',
    };
    const userMembersFilter = {
      mode: FilterMode.Or,
      filters: [membersFilters, userTypeFilters],
      filterGroups: [],
    };
    const filters = {
      mode: FilterMode.And,
      filters: [],
      filterGroups: argsFilters ? [argsFilters, userMembersFilter] : [userMembersFilter],
    };
    return {
      ...args,
      filters,
    };
  }
  return args;
};

export const CAPABILITIES_IN_DRAFT_NAMES = [
  KNOWLEDGE,
  KNOWLEDGE_KNPARTICIPATE,
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPDATE_KNDELETE,
  KNOWLEDGE_KNUPDATE_KNMERGE,
  KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE,
  KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS,
  KNOWLEDGE_KNUPLOAD,
  KNOWLEDGE_KNASKIMPORT,
  KNOWLEDGE_KNENRICHMENT,
  SETTINGS_SETLABELS,
];
