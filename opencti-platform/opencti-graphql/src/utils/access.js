var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { context as telemetryContext, trace } from '@opentelemetry/api';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { STIX_ORGANIZATIONS_UNRESTRICTED } from '../schema/stixDomainObject';
import { generateInternalType, getParentTypes } from '../schema/schemaUtils';
import { telemetry } from '../config/tracing';
import { ACCOUNT_STATUS_ACTIVE } from '../config/conf';
export const DEFAULT_INVALID_CONF_VALUE = 'ChangeMe';
export const BYPASS = 'BYPASS';
export const BYPASS_REFERENCE = 'BYPASSREFERENCE';
export const SETTINGS_SET_ACCESSES = 'SETTINGS_SETACCESSES';
export const TAXIIAPI_SETCOLLECTIONS = 'TAXIIAPI_SETCOLLECTIONS';
export const TAXIIAPI_SETCSVMAPPERS = 'TAXIIAPI_SETCSVMAPPERS';
export const KNOWLEDGE_ORGANIZATION_RESTRICT = 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT';
export const SETTINGS = 'SETTINGS';
export const VIRTUAL_ORGANIZATION_ADMIN = 'VIRTUAL_ORGANIZATION_ADMIN';
export const ROLE_DEFAULT = 'Default';
export const ROLE_ADMINISTRATOR = 'Administrator';
const RETENTION_MANAGER_USER_UUID = '82ed2c6c-eb27-498e-b904-4f2abc04e05f';
export const RULE_MANAGER_USER_UUID = 'f9d7b43f-b208-4c56-8637-375a1ce84943';
export const AUTOMATION_MANAGER_USER_UUID = 'c49fe040-2dad-412d-af07-ce639204ad55';
export const REDACTED_USER_UUID = '31afac4e-6b99-44a0-b91b-e04738d31461';
export const MEMBER_ACCESS_ALL = 'ALL';
export const MEMBER_ACCESS_CREATOR = 'CREATOR';
export const MEMBER_ACCESS_RIGHT_ADMIN = 'admin';
export const MEMBER_ACCESS_RIGHT_EDIT = 'edit';
export const MEMBER_ACCESS_RIGHT_VIEW = 'view';
const MEMBER_ACCESS_RIGHTS = [MEMBER_ACCESS_RIGHT_VIEW, MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_ADMIN];
const administratorRoleId = uuidv4();
export const ADMINISTRATOR_ROLE = {
    id: administratorRoleId,
    internal_id: administratorRoleId,
    name: ROLE_ADMINISTRATOR
};
const defaultRoleId = uuidv4();
export const DEFAULT_ROLE = {
    id: defaultRoleId,
    internal_id: defaultRoleId,
    name: ROLE_DEFAULT
};
export const SYSTEM_USER = {
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
    all_marking: [],
    api_token: '',
    account_lock_after_date: undefined,
    account_status: ACCOUNT_STATUS_ACTIVE,
    administrated_organizations: [],
};
export const RETENTION_MANAGER_USER = {
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
    default_marking: [],
    all_marking: [],
    api_token: '',
    account_lock_after_date: undefined,
    account_status: ACCOUNT_STATUS_ACTIVE,
    administrated_organizations: [],
};
export const RULE_MANAGER_USER = {
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
    default_marking: [],
    all_marking: [],
    api_token: '',
    account_lock_after_date: undefined,
    account_status: ACCOUNT_STATUS_ACTIVE,
    administrated_organizations: [],
};
export const AUTOMATION_MANAGER_USER = {
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
    default_marking: [],
    all_marking: [],
    api_token: '',
    account_lock_after_date: undefined,
    account_status: ACCOUNT_STATUS_ACTIVE,
    administrated_organizations: [],
};
export const REDACTED_USER = {
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
    default_marking: [],
    all_marking: [],
    api_token: '',
    account_lock_after_date: undefined,
    account_status: ACCOUNT_STATUS_ACTIVE,
};
class TracingContext {
    constructor(tracer) {
        this.tracer = tracer;
        this.ctx = undefined;
    }
    getCtx() {
        return this.ctx;
    }
    getTracer() {
        return this.tracer;
    }
    setCurrentCtx(span) {
        this.ctx = trace.setSpan(telemetryContext.active(), span);
    }
}
export const executionContext = (source, auth) => {
    const tracer = trace.getTracer('instrumentation-opencti', '1.0.0');
    const tracing = new TracingContext(tracer);
    return { otp_mandatory: false, source, tracing, user: auth !== null && auth !== void 0 ? auth : undefined };
};
export const INTERNAL_USERS = {
    [SYSTEM_USER.id]: SYSTEM_USER,
    [RETENTION_MANAGER_USER.id]: RETENTION_MANAGER_USER,
    [RULE_MANAGER_USER.id]: RULE_MANAGER_USER,
    [AUTOMATION_MANAGER_USER.id]: AUTOMATION_MANAGER_USER,
    [REDACTED_USER.id]: REDACTED_USER
};
export const isBypassUser = (user) => {
    return R.find((s) => s.name === BYPASS, user.capabilities || []) !== undefined;
};
export const isUserHasCapability = (user, capability) => {
    return isBypassUser(user) || R.find((s) => s.name === capability, user.capabilities || []) !== undefined;
};
export const isUserHasCapabilities = (user, capabilities = []) => {
    return capabilities.every((capability) => isUserHasCapability(user, capability));
};
export const userFilterStoreElements = (context, user, elements) => __awaiter(void 0, void 0, void 0, function* () {
    const userFilterStoreElementsFn = () => __awaiter(void 0, void 0, void 0, function* () {
        // If user have bypass, grant access to all
        if (isBypassUser(user)) {
            return elements;
        }
        // If not filter by the inner markings
        const settings = yield getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS);
        const authorizedMarkings = user.allowed_marking.map((a) => a.internal_id);
        return elements.filter((element) => {
            var _a, _b;
            // 1. Check markings
            const elementMarkings = (_a = element[RELATION_OBJECT_MARKING]) !== null && _a !== void 0 ? _a : [];
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
            const elementOrganizations = (_b = element[RELATION_GRANTED_TO]) !== null && _b !== void 0 ? _b : [];
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
    });
    return telemetry(context, user, 'FILTERING store filter', {
        [SemanticAttributes.DB_NAME]: 'search_engine',
        [SemanticAttributes.DB_OPERATION]: 'read',
    }, userFilterStoreElementsFn);
});
export const isUserCanAccessStoreElement = (context, user, element) => __awaiter(void 0, void 0, void 0, function* () {
    const elements = yield userFilterStoreElements(context, user, [element]);
    return elements.length === 1;
});
export const isUserCanAccessStixElement = (context, user, instance) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c, _d, _e, _f, _g;
    // If user have bypass, grant access to all
    if (isBypassUser(user)) {
        return true;
    }
    // 1. Check markings
    const instanceMarkings = (_a = instance.object_marking_refs) !== null && _a !== void 0 ? _a : [];
    if (instanceMarkings.length > 0) {
        const userMarkings = (user.allowed_marking || []).map((m) => m.standard_id);
        const isUserHaveAccess = instanceMarkings.every((m) => userMarkings.includes(m));
        if (!isUserHaveAccess) {
            return false;
        }
    }
    // 2. Check organizations
    // Allow unrestricted entities
    const entityType = (_d = (_c = (_b = instance.extensions) === null || _b === void 0 ? void 0 : _b[STIX_EXT_OCTI]) === null || _c === void 0 ? void 0 : _c.type) !== null && _d !== void 0 ? _d : generateInternalType(instance);
    const types = [entityType, ...getParentTypes(entityType)];
    if (STIX_ORGANIZATIONS_UNRESTRICTED.some((r) => types.includes(r))) {
        return true;
    }
    // Check restricted elements
    const settings = yield getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS);
    const elementOrganizations = (_g = (_f = (_e = instance.extensions) === null || _e === void 0 ? void 0 : _e[STIX_EXT_OCTI]) === null || _f === void 0 ? void 0 : _f.granted_refs) !== null && _g !== void 0 ? _g : [];
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
});
// region member access
// returns all user member access ids : his id, his organizations ids (and parent organizations), his groups ids
export const computeUserMemberAccessIds = (user) => {
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
export const isDirectAdministrator = (user, element) => {
    const elementAccessIds = element.authorized_members
        .filter((u) => u.access_right === MEMBER_ACCESS_RIGHT_ADMIN)
        .map((u) => u.id);
    const userMemberAccessIds = computeUserMemberAccessIds(user);
    return elementAccessIds.some((a) => userMemberAccessIds.includes(a));
};
export const getUserAccessRight = (user, element) => {
    var _a;
    if (!element.authorized_members) { // no restricted user access on element
        return MEMBER_ACCESS_RIGHT_ADMIN;
    }
    const accessMembers = [...element.authorized_members];
    const userMemberAccessIds = computeUserMemberAccessIds(user);
    const foundAccessMembers = accessMembers.filter((u) => u.id === MEMBER_ACCESS_ALL || userMemberAccessIds.includes(u.id));
    // If user have extended capabilities, is an admin
    if (((_a = element.authorized_authorities) !== null && _a !== void 0 ? _a : []).some((c) => userMemberAccessIds.includes(c) || isUserHasCapability(user, c))) {
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
export const validateUserAccessOperation = (user, element, operation) => {
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
export const isValidMemberAccessRight = (accessRight) => {
    return accessRight && MEMBER_ACCESS_RIGHTS.includes(accessRight);
};
