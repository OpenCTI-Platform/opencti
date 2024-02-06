var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { uniq } from 'ramda';
import { isEmptyField } from '../database/utils';
import { isUserHasCapabilities, MEMBER_ACCESS_ALL, MEMBER_ACCESS_CREATOR, MEMBER_ACCESS_RIGHT_ADMIN, SYSTEM_USER, validateUserAccessOperation } from './access';
import { findAllMembers, findById as findUser } from '../domain/user';
import { findById as findGroup } from '../domain/group';
import { findById as findOrganization } from '../modules/organization/organization-domain';
import { RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO } from '../schema/internalRelationship';
export const getAuthorizedMembers = (context, user, entity) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b;
    let authorizedMembers = [];
    if (isEmptyField(entity.authorized_members)) {
        return authorizedMembers;
    }
    if (!validateUserAccessOperation(user, entity, 'manage-access')) {
        return authorizedMembers; // return empty if user doesn't have the right access_right
    }
    const membersIds = ((_a = entity.authorized_members) !== null && _a !== void 0 ? _a : []).map((e) => e.id);
    const args = {
        connectionFormat: false,
        first: 100,
        filters: {
            mode: 'and',
            filters: [{ key: 'internal_id', values: membersIds }],
            filterGroups: [],
        },
    };
    const members = yield findAllMembers(context, user, args);
    authorizedMembers = ((_b = entity.authorized_members) !== null && _b !== void 0 ? _b : []).map((am) => {
        var _a, _b;
        const member = members.find((m) => m.id === am.id);
        return { id: am.id, name: (_a = member === null || member === void 0 ? void 0 : member.name) !== null && _a !== void 0 ? _a : '', entity_type: (_b = member === null || member === void 0 ? void 0 : member.entity_type) !== null && _b !== void 0 ? _b : '', access_right: am.access_right };
    });
    return authorizedMembers;
});
export const containsValidAdmin = (context, authorized_members, requiredCapabilities = []) => __awaiter(void 0, void 0, void 0, function* () {
    const adminIds = authorized_members
        .filter((n) => n.access_right === MEMBER_ACCESS_RIGHT_ADMIN)
        .map((e) => e.id);
    if (adminIds.length === 0) { // no admin
        return false;
    }
    if (adminIds.includes(MEMBER_ACCESS_ALL) || adminIds.includes(MEMBER_ACCESS_CREATOR)) { // everyone  or creator is admin
        return true;
    }
    // find the users that have admin rights
    const groups = (yield Promise.all(adminIds.map((id) => findGroup(context, SYSTEM_USER, id))))
        .filter((n) => n);
    const organizations = (yield Promise.all(adminIds.map((id) => findOrganization(context, SYSTEM_USER, id))))
        .filter((n) => n);
    const groupsMembersIds = uniq(groups.map((group) => group[RELATION_MEMBER_OF]).flat());
    const organizationsMembersIds = uniq(organizations.map((o) => o[RELATION_PARTICIPATE_TO]).flat());
    const userIds = adminIds
        .filter((id) => !groups.map((o) => o.id).includes(id)
        && !organizations.map((o) => o.id).includes(id))
        .concat(groupsMembersIds, organizationsMembersIds);
    // resolve the users
    const users = yield Promise.all(userIds.map((userId) => findUser(context, SYSTEM_USER, userId)));
    // restrict to the users that exist and have admin exploration capability
    const authorizedUsers = users.filter((u) => u && isUserHasCapabilities(u, requiredCapabilities));
    // at least 1 user with admin access and admin exploration capability
    return authorizedUsers.length > 0;
});
