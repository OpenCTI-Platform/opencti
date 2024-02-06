var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { createEntity, patchAttribute } from '../../database/middleware';
import { internalFindByIds, listAllEntities, listAllFromEntitiesThroughRelations, listEntitiesPaginated, listEntitiesThroughRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { notify } from '../../database/redis';
import { ENTITY_TYPE_IDENTITY_SECTOR } from '../../schema/stixDomainObject';
import { RELATION_PART_OF } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from './organization-types';
import { FunctionalError } from '../../config/errors';
import { isUserHasCapability, SETTINGS_SET_ACCESSES } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { userSessionRefresh } from '../../domain/user';
// region CRUD
export const findById = (context, user, organizationId) => {
    return storeLoadById(context, user, organizationId, ENTITY_TYPE_IDENTITY_ORGANIZATION);
};
export const findAll = (context, user, args) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_IDENTITY_ORGANIZATION], args);
};
export const addOrganization = (context, user, organization) => __awaiter(void 0, void 0, void 0, function* () {
    const organizationWithClass = Object.assign({ identity_class: ENTITY_TYPE_IDENTITY_ORGANIZATION.toLowerCase() }, organization);
    const created = yield createEntity(context, user, organizationWithClass, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
export const editAuthorizedAuthorities = (context, user, organizationId, input) => __awaiter(void 0, void 0, void 0, function* () {
    const patch = { authorized_authorities: input };
    const { element } = yield patchAttribute(context, user, organizationId, ENTITY_TYPE_IDENTITY_ORGANIZATION, patch);
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, element, user);
});
export const organizationAdminAdd = (context, user, organizationId, memberId) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    // Get Orga and members
    const organization = yield findById(context, user, organizationId);
    const members = yield listAllFromEntitiesThroughRelations(context, user, organizationId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_USER);
    const updatedUser = members.find(({ id }) => id === memberId);
    // Check if user is part of Orga. If not, throw exception
    if (!updatedUser) {
        throw FunctionalError('User is not part of the organization');
    }
    // Add user to organization admins list
    const updated = yield editAuthorizedAuthorities(context, user, organizationId, [...((_a = organization.authorized_authorities) !== null && _a !== void 0 ? _a : []), memberId]);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `Promoting \`${updatedUser.name}\` as admin orga of \`${organization.name}\``,
        context_data: { id: updated.id, entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION, input: { organizationId, memberId } }
    });
    yield userSessionRefresh(memberId);
    return updated;
});
export const organizationAdminRemove = (context, user, organizationId, memberId) => __awaiter(void 0, void 0, void 0, function* () {
    var _b, _c, _d;
    // Get Orga and members
    const organization = yield findById(context, user, organizationId);
    const members = yield listAllFromEntitiesThroughRelations(context, user, organizationId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_USER);
    const updatedUser = members.find(({ id }) => id === memberId);
    // Check if user is part of Orga and is orga_admin. If not, throw exception
    if (!updatedUser) {
        throw FunctionalError('User is not part of the organization');
    }
    // Remove user from organization admins list
    const indexOfMember = ((_b = organization.authorized_authorities) !== null && _b !== void 0 ? _b : []).indexOf(memberId);
    ((_c = organization.authorized_authorities) !== null && _c !== void 0 ? _c : []).splice(indexOfMember, 1);
    const updated = yield editAuthorizedAuthorities(context, user, organizationId, ((_d = organization.authorized_authorities) !== null && _d !== void 0 ? _d : []));
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `Demoting \`${updatedUser.name}\` as admin orga of \`${organization.name}\``,
        context_data: { id: updated.id, entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION, input: { organizationId, memberId } }
    });
    yield userSessionRefresh(memberId);
    return updated;
});
export const findGrantableGroups = (context, user, organization) => __awaiter(void 0, void 0, void 0, function* () {
    // This will be removed when group is a module and types are correctly defined
    return internalFindByIds(context, user, organization.grantable_groups);
});
export const buildAdministratedOrganizations = (context, user, member) => __awaiter(void 0, void 0, void 0, function* () {
    let organizations;
    if (isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
        organizations = yield listAllEntities(context, user, [ENTITY_TYPE_IDENTITY_ORGANIZATION]);
    }
    else {
        organizations = user.administrated_organizations;
    }
    return (organizations !== null && organizations !== void 0 ? organizations : []).filter((o) => { var _a; return (_a = o.authorized_authorities) === null || _a === void 0 ? void 0 : _a.includes(member.id); });
});
// endregion
export const organizationSectorsPaginated = (context, user, organizationId, args) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, organizationId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR, false, args);
});
export const organizationMembersPaginated = (context, user, organizationId, args) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, organizationId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_USER, true, args);
});
export const parentOrganizationsPaginated = (context, user, organizationId, args) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, organizationId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION, false, args);
});
export const childOrganizationsPaginated = (context, user, organizationId, args) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, organizationId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION, true, args);
});
// endregion
