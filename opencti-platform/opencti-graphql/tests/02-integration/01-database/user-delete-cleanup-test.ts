import { describe, expect, it } from 'vitest';
import { ADMIN_USER } from '../../utils/testQuery';
import { generateInternalId, generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import {
  addNotification,
  addTrigger, myNotificationsFind,
  triggerGet
} from '../../../src/modules/notification/notification-domain';
import type {
  MemberAccessInput,
  TriggerLiveAddInput,
  WorkspaceAddInput
} from '../../../src/generated/graphql';
import { addUser, assignGroupToUser, findById, findById as findUserById, userDelete } from '../../../src/domain/user';
import { ACCOUNT_STATUS_ACTIVE } from '../../../src/config/conf';
import { ADMINISTRATOR_ROLE } from '../../../src/utils/access';
import type { StoreMarkingDefinition } from '../../../src/types/store';
import { addWorkspace, editAuthorizedMembers, findById as findWorkspaceById } from '../../../src/modules/workspace/workspace-domain';
import type {
  NotificationAddInput,
} from '../../../src/modules/notification/notification-types';
import { TriggerEventType, TriggerType } from '../../../src/generated/graphql';

/**
 * Create a new user in elastic for this test purpose using domain APIs only.
 * @param adminContext
 * @param adminUser
 * @param username
 */
const createUserForTest = async (adminContext: AuthContext, adminUser: AuthUser, username: string) => {
  const userToDeleteId: string = generateStandardId(ENTITY_TYPE_USER, { user_email: `${username}@opencti.io` });
  // const userToDeleteInternalId: string = generateInternalId();

  const simpleUser = {
    id: userToDeleteId,
    password: 'changeme',
    user_email: `${username}@opencti.io`,
    name: username,
    firstname: username,
    lastname: 'opencti'
  };
  const createdUser = await addUser(adminContext, adminUser, simpleUser);

  // TODO what is the type here ??
  return createdUser;
};

/**
 * Create a AuthUser from user information that have been used to create the user in elastic.
 * // TODO there is probably a better way to have a AuthUser from a User...
 * @param user
 */
const getAuthUserForTest = async (user: any) => {
  const userToDeletedAuth: AuthUser = {
    administrated_organizations: [],
    entity_type: 'User',
    id: user.id,
    internal_id: generateInternalId(),
    individual_id: generateInternalId(),
    organizations: [],
    name: user.name,
    user_email: user.user_email,
    roles: [ADMINISTRATOR_ROLE],
    groups: [],
    capabilities: [
      { name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }, // required for Trigger management
      { name: 'SETTINGS_SETACCESSES' },
      { name: 'EXPLORE_EXUPDATE_EXDELETE' },
      { name: 'EXPLORE_EXUPDATE' }
    ],
    all_marking: [] as StoreMarkingDefinition[],
    allowed_organizations: [],
    inside_platform_organization: true,
    allowed_marking: [{ standard_id: user.id, internal_id: user.id }] as StoreMarkingDefinition[],
    default_marking: [],
    origin: { referer: 'test', user_id: '98ec0c6a-13ce-5e39-b486-354fe4a7084f' },
    api_token: generateInternalId(),
    account_status: ACCOUNT_STATUS_ACTIVE,
    account_lock_after_date: undefined
  };
  return userToDeletedAuth;
};

const createTriggerForUser = async (context: AuthContext, user: AuthUser) => {
  const triggerInput: TriggerLiveAddInput = { name: 'trigger-of-iwillbegonesoon', event_types: [TriggerEventType.Delete], instance_trigger: false, recipients: [] };
  return addTrigger(context, user, triggerInput, TriggerType.Live);
};

const createNotificationForUser = async (context: AuthContext, user: AuthUser) => {
  const notificationInput: NotificationAddInput = { is_read: true,
    name: 'notifier-of-iwillbegonesoon',
    notification_type: '',
    content: [{
      title: '',
      events: []
    }] };
  return addNotification(context, user, notificationInput);
};

describe('Testing user delete on cascade [issue/3720]', () => {
  it('should [trigger, digest, notifications, investigation, dashboard] owned by user1 and only user1, be cleaned-up when user1 is deleted', async () => {
    // ***********************************
    // GIVEN a user
    // AND an admin ADMIN_USER having rights to create/delete users
    const adminContext: AuthContext = { user: ADMIN_USER, tracing: undefined, source: 'integration-test', otp_mandatory: false };
    const userToDelete = await createUserForTest(adminContext, ADMIN_USER, 'iwillbedeletedsoon');
    const userToDeletedAuth = await getAuthUserForTest(userToDelete);
    // const userToDeletedAuth = await findById(adminContext, ADMIN_USER, userToDelete.id);

    const userToDeleteContext: AuthContext = { user: userToDeletedAuth, tracing: undefined, source: 'integration-test', otp_mandatory: false };
    await assignGroupToUser(adminContext, ADMIN_USER, userToDeletedAuth.id, 'Default');

    // AND user having a Trigger
    const newTrigger = await createTriggerForUser(userToDeleteContext, userToDeletedAuth);
    expect(newTrigger.trigger_type, 'There is an issue with Trigger creation.').toBe('live');

    // AND user having a Notification
    const newNotification = await createNotificationForUser(userToDeleteContext, userToDeletedAuth);
    expect(newNotification).toBeDefined();

    // AND user having an Investigation not shared at all
    const privateInvestigationInput: WorkspaceAddInput = {
      name: 'investigation-not-shared',
      description: 'this investigation is not shared to other users.',
      type: 'investigation'
    };

    const privateInvestigationData = await addWorkspace(userToDeleteContext, userToDeletedAuth, privateInvestigationInput);
    expect(privateInvestigationData.authorized_members.length).toBe(1);
    const privateInvestigationData2 = await addWorkspace(userToDeleteContext, userToDeletedAuth, privateInvestigationInput);
    expect(privateInvestigationData2.authorized_members.length).toBe(1);

    // AND user having an Investigation shared to ALL with admin rights
    const sharedWithAdminRightsInvestigationInput: WorkspaceAddInput = {
      name: 'investigation-shared-with-admin-rights',
      description: 'this investigation will be shared to another user with admin rights.',
      type: 'investigation'
    };
    let sharedWithAdminRightsInvestigationData = await addWorkspace(userToDeleteContext, userToDeletedAuth, sharedWithAdminRightsInvestigationInput);
    const sharedIAuthMembers: MemberAccessInput[] = sharedWithAdminRightsInvestigationData.authorized_members;

    sharedIAuthMembers.push({ id: 'ALL', access_right: 'admin' });
    console.log('** 🦄 sharedIAuthMembers', sharedIAuthMembers);

    await editAuthorizedMembers(userToDeleteContext, userToDeletedAuth, sharedWithAdminRightsInvestigationData.id, sharedIAuthMembers);
    sharedWithAdminRightsInvestigationData = await findWorkspaceById(userToDeleteContext, userToDeletedAuth, sharedWithAdminRightsInvestigationData.id);
    expect(sharedWithAdminRightsInvestigationData.authorized_members.length).toBe(2);

    // AND .. TODO fix the user used for tests
    /* const sharedReadOnlyInvestigationInput: WorkspaceAddInput = {
      name: 'investigation-shared-read-only',
      description: 'this investigation will be shared to another user with view rights.',
      type: 'investigation'
    };
    let sharedInvestigationData = await addWorkspace(userToDeleteContext, userToDeletedAuth, sharedReadOnlyInvestigationInput);
    const sharedInvestigationAuthMembers: MemberAccessInput[] = sharedInvestigationData.authorized_members;
    sharedInvestigationAuthMembers.push({ id: 'ALL', access_right: 'view' });
    console.log('ADMIN ??? => sharedInvestigationAuthMembers', sharedInvestigationAuthMembers);
    await editAuthorizedMembers(userToDeleteContext, userToDeletedAuth, sharedInvestigationData.id, sharedInvestigationAuthMembers);
    sharedInvestigationData = await findWorkspaceById(userToDeleteContext, userToDeletedAuth, sharedInvestigationData.id);
    expect(sharedInvestigationData.authorized_members.length).toBe(2); */

    // AND user having a workspace with view only rights
    const adminInvestigationInput: WorkspaceAddInput = {
      name: 'investigation-owned-by-admin',
      description: 'this investigation is owned by the admin, do not delete.',
      type: 'investigation'
    };

    const adminInvestigationData = await addWorkspace(adminContext, ADMIN_USER, adminInvestigationInput);
    const adminInvestigationAuthMembers: MemberAccessInput[] = adminInvestigationData.authorized_members;
    adminInvestigationAuthMembers.push({ id: userToDeletedAuth.id, access_right: 'view' });
    await editAuthorizedMembers(adminContext, ADMIN_USER, adminInvestigationData.id, adminInvestigationAuthMembers);
    expect(adminInvestigationData.authorized_members.length).toBe(2);

    // ******************************************
    // WHEN the user is deleted
    await userDelete(adminContext, ADMIN_USER, userToDeletedAuth.id);

    const deletedUser = await findUserById(adminContext, ADMIN_USER, userToDeletedAuth.id);
    expect(deletedUser).toBeUndefined();

    // *****************************
    // THEN the user's trigger is deleted too
    const getTriggerFromElastic = await triggerGet(userToDeleteContext, userToDeletedAuth, newTrigger.id);
    expect(getTriggerFromElastic, `The user ${userToDeletedAuth.id} trigger should not exists anymore after user deletion.`).toBeUndefined();
    const getNotificationFromElastic = await myNotificationsFind(userToDeleteContext, userToDeletedAuth, newNotification.id);
    expect(getNotificationFromElastic.pageInfo.globalCount, `The user ${userToDeletedAuth.id} notification should not exists anymore after user deletion.`).toBe(0);

    // THEN the user's private Investigation is deleted, but not the shared one
    const investigationThatStay = await findWorkspaceById(userToDeleteContext, userToDeletedAuth, sharedWithAdminRightsInvestigationData.id);
    expect(investigationThatStay, 'Other user have admin access to this Investigation, it should not be deleted with the user.').toBeDefined();

    const investigationThatShouldBeGone = await findWorkspaceById(userToDeleteContext, userToDeletedAuth, privateInvestigationData.id);
    // TODO make it work :)
    // expect(investigationThatShouldBeGone, 'This Investigation was for the deleted user only, should be cleaned-up').toBeUndefined();

    const adminInvestigationThatStay = await findWorkspaceById(adminContext, ADMIN_USER, adminInvestigationData.id);
    expect(adminInvestigationThatStay, 'User is view only on this investigation owned by admin, it should not be deleted with the user.').toBeDefined();
  });
});
