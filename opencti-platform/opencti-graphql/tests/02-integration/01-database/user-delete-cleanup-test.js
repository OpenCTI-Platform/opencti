var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { describe, expect, it } from 'vitest';
import { ADMIN_USER, AMBER_STRICT_GROUP } from '../../utils/testQuery';
import { generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { addNotification, addTrigger, myNotificationsFind, triggerGet } from '../../../src/modules/notification/notification-domain';
import { addUser, assignGroupToUser, findById as findUserById, isUserTheLastAdmin, userDelete } from '../../../src/domain/user';
import { addWorkspace, editAuthorizedMembers, findById as findWorkspaceById } from '../../../src/modules/workspace/workspace-domain';
import { TriggerEventType, TriggerType } from '../../../src/generated/graphql';
/**
 * Create a new user in elastic for this test purpose using domain APIs only.
 * @param adminContext
 * @param adminUser
 * @param username
 */
const createUserForTest = (adminContext, adminUser, username) => __awaiter(void 0, void 0, void 0, function* () {
    const userToDeleteId = generateStandardId(ENTITY_TYPE_USER, { user_email: `${username}@opencti.io` });
    const simpleUser = {
        id: userToDeleteId,
        password: 'changeme',
        user_email: `${username}@opencti.io`,
        name: username,
        firstname: username,
        lastname: 'opencti'
    };
    const userAdded = yield addUser(adminContext, adminUser, simpleUser);
    yield assignGroupToUser(adminContext, adminUser, userAdded.id, AMBER_STRICT_GROUP.name);
    return findUserById(adminContext, adminUser, userAdded.id);
});
const createTriggerForUser = (context, user) => __awaiter(void 0, void 0, void 0, function* () {
    const triggerInput = { name: 'trigger-of-iwillbegonesoon', event_types: [TriggerEventType.Delete], instance_trigger: false, recipients: [] };
    return addTrigger(context, user, triggerInput, TriggerType.Live);
});
const createNotificationForUser = (context, user) => __awaiter(void 0, void 0, void 0, function* () {
    const notificationInput = { is_read: true,
        name: 'notifier-of-iwillbegonesoon',
        notification_type: '',
        notification_content: [{
                title: '',
                events: []
            }] };
    return addNotification(context, user, notificationInput);
});
describe('Testing user delete on cascade [issue/3720]', () => {
    it('should [trigger, digest, notifications, investigation, dashboard] owned by user1 and only user1, be cleaned-up when user1 is deleted', () => __awaiter(void 0, void 0, void 0, function* () {
        try {
            // ***********************************
            // GIVEN a user
            // AND an admin ADMIN_USER having rights to create/delete users
            const adminContext = { user: ADMIN_USER, tracing: undefined, source: 'integration-test', otp_mandatory: false };
            const userToDeletedAuth = yield createUserForTest(adminContext, ADMIN_USER, 'iwillbedeletedsoon3');
            const userToDeleteContext = { user: userToDeletedAuth, tracing: undefined, source: 'integration-test', otp_mandatory: false };
            // AND user having a Trigger
            const newTrigger = yield createTriggerForUser(userToDeleteContext, userToDeletedAuth);
            expect(newTrigger.trigger_type, 'There is an issue with Trigger creation.').toBe('live');
            // AND user having a Notification
            const newNotification = yield createNotificationForUser(userToDeleteContext, userToDeletedAuth);
            expect(newNotification).toBeDefined();
            // AND user having an Investigation not shared at all
            const privateInvestigationInput = {
                name: 'investigation-not-shared',
                description: 'this investigation is not shared to other users.',
                type: 'investigation'
            };
            const privateInvestigationData = yield addWorkspace(userToDeleteContext, userToDeletedAuth, privateInvestigationInput);
            expect(privateInvestigationData.authorized_members.length).toBe(1);
            // AND user having an Investigation shared to ALL with admin rights
            const sharedWithAdminRightsInvestigationInput = {
                name: 'investigation-shared-with-admin-rights',
                description: 'this investigation will be shared to another user with admin rights.',
                type: 'investigation'
            };
            let sharedWithAdminRightsInvestigationData = yield addWorkspace(userToDeleteContext, userToDeletedAuth, sharedWithAdminRightsInvestigationInput);
            const sharedIAuthMembers = sharedWithAdminRightsInvestigationData.authorized_members;
            sharedIAuthMembers.push({ id: 'ALL', access_right: 'admin' });
            yield editAuthorizedMembers(userToDeleteContext, userToDeletedAuth, sharedWithAdminRightsInvestigationData.id, sharedIAuthMembers);
            sharedWithAdminRightsInvestigationData = yield findWorkspaceById(userToDeleteContext, userToDeletedAuth, sharedWithAdminRightsInvestigationData.id);
            expect(sharedWithAdminRightsInvestigationData.authorized_members.length).toBe(2);
            // AND an investigation shared but the user is the last admin
            const sharedReadOnlyInvestigationInput = {
                name: 'investigation-shared-read-only',
                description: 'this investigation will be shared to another user with view rights.',
                type: 'investigation'
            };
            let sharedInvestigationData = yield addWorkspace(userToDeleteContext, userToDeletedAuth, sharedReadOnlyInvestigationInput);
            const sharedInvestigationAuthMembers = sharedInvestigationData.authorized_members;
            sharedInvestigationAuthMembers.push({ id: 'ALL', access_right: 'view' });
            yield editAuthorizedMembers(adminContext, ADMIN_USER, sharedInvestigationData.id, sharedInvestigationAuthMembers);
            sharedInvestigationData = yield findWorkspaceById(userToDeleteContext, userToDeletedAuth, sharedInvestigationData.id);
            expect(sharedInvestigationData.authorized_members.length).toBe(2);
            // AND user having a workspace with view only rights
            const adminInvestigationInput = {
                name: 'investigation-owned-by-admin',
                description: 'this investigation is owned by the admin, do not delete.',
                type: 'investigation'
            };
            const adminInvestigationData = yield addWorkspace(adminContext, ADMIN_USER, adminInvestigationInput);
            const adminInvestigationAuthMembers = adminInvestigationData.authorized_members;
            adminInvestigationAuthMembers.push({ id: userToDeletedAuth.id, access_right: 'view' });
            yield editAuthorizedMembers(adminContext, ADMIN_USER, adminInvestigationData.id, adminInvestigationAuthMembers);
            expect(adminInvestigationData.authorized_members.length).toBe(2);
            // ******************************************
            // WHEN the user is deleted
            yield userDelete(adminContext, ADMIN_USER, userToDeletedAuth.id);
            const deletedUser = yield findUserById(adminContext, ADMIN_USER, userToDeletedAuth.id);
            expect(deletedUser).toBeUndefined();
            // *****************************
            // THEN the user's trigger is deleted too
            const getTriggerFromElastic = yield triggerGet(userToDeleteContext, userToDeletedAuth, newTrigger.id);
            expect(getTriggerFromElastic, `The user ${userToDeletedAuth.id} trigger should not exists anymore after user deletion.`).toBeUndefined();
            const getNotificationFromElastic = yield myNotificationsFind(userToDeleteContext, userToDeletedAuth, newNotification.id);
            expect(getNotificationFromElastic.pageInfo.globalCount, `The user ${userToDeletedAuth.id} notification should not exists anymore after user deletion.`).toBe(0);
            // THEN the user's private Investigation is deleted, but not the shared one
            const investigationThatStay = yield findWorkspaceById(userToDeleteContext, userToDeletedAuth, sharedWithAdminRightsInvestigationData.id);
            expect(investigationThatStay, 'Other user have admin access to this Investigation, it should not be deleted with the user.').toBeDefined();
            const investigationThatShouldBeGone = yield findWorkspaceById(userToDeleteContext, userToDeletedAuth, privateInvestigationData.id);
            expect(investigationThatShouldBeGone, 'This Investigation was for the deleted user only, should be cleaned-up').toBeUndefined();
            const sharedInvestigationThatShouldBeGone = yield findWorkspaceById(userToDeleteContext, userToDeletedAuth, sharedInvestigationData.id);
            expect(sharedInvestigationThatShouldBeGone, 'This Investigation was shared but no one else is admin, should be cleaned-up').toBeUndefined();
            const adminInvestigationThatStay = yield findWorkspaceById(adminContext, ADMIN_USER, adminInvestigationData.id);
            expect(adminInvestigationThatStay, 'User is view only on this investigation owned by admin, it should not be deleted with the user.').toBeDefined();
        }
        catch (e) {
            console.log(JSON.stringify(e));
        }
    }));
    it('should data without authorized_member not throw exception during user deletion.', () => __awaiter(void 0, void 0, void 0, function* () {
        // for some reason this can happend, see https://github.com/OpenCTI-Platform/opencti/issues/5580
        const isLastAdminResult = isUserTheLastAdmin(ADMIN_USER.id, undefined);
        expect(true, 'No exception should be raised here').toBe(true);
        expect(isLastAdminResult, 'An entity without authorized_member data should not block deletion.').toBe(false);
    }));
});
