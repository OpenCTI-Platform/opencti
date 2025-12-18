import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, AMBER_STRICT_GROUP, GREEN_GROUP, PLATFORM_ORGANIZATION, TEST_ORGANIZATION, testContext } from '../../utils/testQuery';
import { generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { addNotification, addTrigger, myNotificationsFind, triggerGet } from '../../../src/modules/notification/notification-domain';
import type { MemberAccessInput, TriggerLiveAddInput, UserAddInput, WorkspaceAddInput } from '../../../src/generated/graphql';
import { TriggerEventType, TriggerType } from '../../../src/generated/graphql';
import {
  addUser,
  assignGroupToUser,
  authenticateUserByTokenOrUserId,
  findById,
  findById as findUserById,
  isUserTheLastAdmin,
  userAddRelation,
  userDelete,
} from '../../../src/domain/user';
import { addWorkspace, findById as findWorkspaceById, workspaceEditAuthorizedMembers } from '../../../src/modules/workspace/workspace-domain';
import type { NotificationAddInput } from '../../../src/modules/notification/notification-types';
import { getFakeAuthUser, getGroupEntity, getOrganizationEntity } from '../../utils/domainQueryHelper';
import { deleteElementById } from '../../../src/database/middleware';
import { unSetOrganization, setOrganization } from '../../utils/testQueryHelper';
import { type BasicStoreEntityOrganization, ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { SETTINGS_SET_ACCESSES } from '../../../src/utils/access';
import type { Group } from '../../../src/types/group';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { addOrganization } from '../../../src/modules/organization/organization-domain';
import { addSector } from '../../../src/domain/sector';
import { RELATION_PARTICIPATE_TO } from '../../../src/schema/internalRelationship';
import type { BasicStoreEntity } from '../../../src/types/store';
import { ENTITY_TYPE_IDENTITY_SECTOR } from '../../../src/schema/stixDomainObject';
import type { BasicStoreEntityWorkspace, StoreEntityWorkspace } from '../../../src/modules/workspace/workspace-types';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';

/**
 * Create a new user in elastic for this test purpose using domain APIs only.
 * @param adminContext
 * @param adminUser
 * @param username
 */
const createUserForTest = async (adminContext: AuthContext, adminUser: AuthUser, username: string) => {
  const userToDeleteId: string = generateStandardId(ENTITY_TYPE_USER, { user_email: `${username}@opencti.io` });

  const simpleUser = {
    id: userToDeleteId,
    password: 'changeme',
    user_email: `${username}@opencti.io`,
    name: username,
    firstname: username,
    lastname: 'opencti',
  };
  const userAdded = await addUser(adminContext, adminUser, simpleUser);
  await assignGroupToUser(adminContext, adminUser, userAdded.id, AMBER_STRICT_GROUP.name);
  return findUserById(adminContext, adminUser, userAdded.id);
};

const createTriggerForUser = async (context: AuthContext, user: AuthUser) => {
  const triggerInput: TriggerLiveAddInput = { name: 'trigger-of-iwillbegonesoon', event_types: [TriggerEventType.Delete], instance_trigger: false, recipients: [] };
  return addTrigger(context, user, triggerInput, TriggerType.Live);
};

const createNotificationForUser = async (context: AuthContext, user: AuthUser) => {
  const notificationInput: NotificationAddInput = { is_read: true,
    name: 'notifier-of-iwillbegonesoon',
    notification_type: '',
    notification_content: [{
      title: '',
      events: [],
    }],
    user_id: user.id,
  };
  return addNotification(context, user, notificationInput);
};

describe('Testing user delete on cascade [issue/3720]', () => {
  it('should [trigger, digest, notifications, investigation, dashboard] owned by user1 and only user1, be cleaned-up when user1 is deleted', async () => {
    // ***********************************
    // GIVEN a user
    // AND an admin ADMIN_USER having rights to create/delete users
    const adminContext: AuthContext = { user: ADMIN_USER, tracing: undefined, source: 'integration-test', otp_mandatory: false, user_inside_platform_organization: false };
    const userToDeletedAuth = await createUserForTest(adminContext, ADMIN_USER, 'iwillbegonesoon') as AuthUser;
    const userToDeleteContext: AuthContext = { user: userToDeletedAuth, tracing: undefined, source: 'integration-test', otp_mandatory: false, user_inside_platform_organization: false };

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
      type: 'investigation',
    };

    const privateInvestigationData = await addWorkspace(userToDeleteContext, userToDeletedAuth, privateInvestigationInput);
    expect(privateInvestigationData.restricted_members.length).toBe(1);

    // AND user having an Investigation shared to ALL with admin rights
    const sharedWithAdminRightsInvestigationInput: WorkspaceAddInput = {
      name: 'investigation-shared-with-admin-rights',
      description: 'this investigation will be shared to another user with admin rights.',
      type: 'investigation',
    };
    let sharedWithAdminRightsInvestigationData: StoreEntityWorkspace | BasicStoreEntityWorkspace = await addWorkspace(
      userToDeleteContext,
      userToDeletedAuth,
      sharedWithAdminRightsInvestigationInput,
    );
    const sharedIAuthMembers: MemberAccessInput[] = sharedWithAdminRightsInvestigationData.restricted_members;
    sharedIAuthMembers.push({ id: 'ALL', access_right: 'admin' });

    await workspaceEditAuthorizedMembers(userToDeleteContext, userToDeletedAuth, sharedWithAdminRightsInvestigationData.id, sharedIAuthMembers);
    sharedWithAdminRightsInvestigationData = await findWorkspaceById(userToDeleteContext, userToDeletedAuth, sharedWithAdminRightsInvestigationData.id);
    expect(sharedWithAdminRightsInvestigationData.restricted_members.length).toBe(2);

    // AND an investigation shared but the user is the last admin
    const sharedReadOnlyInvestigationInput: WorkspaceAddInput = {
      name: 'investigation-shared-read-only',
      description: 'this investigation will be shared to another user with view rights.',
      type: 'investigation',
    };
    let sharedInvestigationData: StoreEntityWorkspace | BasicStoreEntityWorkspace = await addWorkspace(userToDeleteContext, userToDeletedAuth, sharedReadOnlyInvestigationInput);
    const sharedInvestigationAuthMembers: MemberAccessInput[] = sharedInvestigationData.restricted_members;
    sharedInvestigationAuthMembers.push({ id: 'ALL', access_right: 'view' });

    await workspaceEditAuthorizedMembers(adminContext, ADMIN_USER, sharedInvestigationData.id, sharedInvestigationAuthMembers);
    sharedInvestigationData = await findWorkspaceById(userToDeleteContext, userToDeletedAuth, sharedInvestigationData.id);
    expect(sharedInvestigationData.restricted_members.length).toBe(2);

    // AND user having a workspace with view only rights
    const adminInvestigationInput: WorkspaceAddInput = {
      name: 'investigation-owned-by-admin',
      description: 'this investigation is owned by the admin, do not delete.',
      type: 'investigation',
    };

    const adminInvestigationData = await addWorkspace(adminContext, ADMIN_USER, adminInvestigationInput);
    const adminInvestigationAuthMembers: MemberAccessInput[] = adminInvestigationData.restricted_members;
    adminInvestigationAuthMembers.push({ id: userToDeletedAuth.id, access_right: 'view' });
    await workspaceEditAuthorizedMembers(adminContext, ADMIN_USER, adminInvestigationData.id, adminInvestigationAuthMembers);
    expect(adminInvestigationData.restricted_members.length).toBe(2);

    // ******************************************
    // WHEN the user is deleted
    await userDelete(adminContext, ADMIN_USER, userToDeletedAuth.id);

    const deletedUser = await findUserById(adminContext, ADMIN_USER, userToDeletedAuth.id);
    expect(deletedUser).toBeUndefined();

    // *****************************
    // THEN the user's trigger is deleted too
    const getTriggerFromElastic = await triggerGet(adminContext, ADMIN_USER, newTrigger.id);
    expect(getTriggerFromElastic, `The user ${userToDeletedAuth.id} trigger should not exists anymore after user deletion. ${JSON.stringify(getTriggerFromElastic)}`).toBeUndefined();
    const getNotificationFromElastic = await myNotificationsFind(userToDeleteContext, userToDeletedAuth, newNotification.id);
    expect(getNotificationFromElastic.pageInfo.globalCount, `The user ${userToDeletedAuth.id} notification should not exists anymore after user deletion.`).toBe(0);

    // THEN the user's private Investigation is deleted, but not the shared one
    const investigationThatStay = await findWorkspaceById(userToDeleteContext, userToDeletedAuth, sharedWithAdminRightsInvestigationData.id);
    expect(investigationThatStay, 'Other user have admin access to this Investigation, it should not be deleted with the user.').toBeDefined();

    const investigationThatShouldBeGone = await findWorkspaceById(userToDeleteContext, userToDeletedAuth, privateInvestigationData.id);
    expect(investigationThatShouldBeGone, 'This Investigation was for the deleted user only, should be cleaned-up').toBeUndefined();

    const sharedInvestigationThatShouldBeGone = await findWorkspaceById(userToDeleteContext, userToDeletedAuth, sharedInvestigationData.id);
    expect(sharedInvestigationThatShouldBeGone, 'This Investigation was shared but no one else is admin, should be cleaned-up').toBeUndefined();

    const adminInvestigationThatStay = await findWorkspaceById(adminContext, ADMIN_USER, adminInvestigationData.id);
    expect(adminInvestigationThatStay, 'User is view only on this investigation owned by admin, it should not be deleted with the user.').toBeDefined();
  });
  it('should data without authorized_member not throw exception during user deletion.', async () => {
    // for some reason this can happend, see https://github.com/OpenCTI-Platform/opencti/issues/5580
    const isLastAdminResult = isUserTheLastAdmin(ADMIN_USER.id, undefined);
    expect(true, 'No exception should be raised here').toBe(true);
    expect(isLastAdminResult, 'An entity without authorized_member data should not block deletion.').toBe(false);
  });
});

describe('Service account User coverage', async () => {
  const authUser = getFakeAuthUser('Platform administrator');
  authUser.capabilities = [{ name: SETTINGS_SET_ACCESSES }];

  it('should get email if userAdd service account with email setup', async () => {
    const USER: UserAddInput = {
      user_email: 'trucmuche@opencti',
      name: 'Service account',
      user_service_account: true,
      groups: [],
      objectOrganization: [],
    };
    const userAddResult = await addUser(testContext, authUser, USER);
    const userCreated: AuthUser = await findById(testContext, authUser, userAddResult.id);

    expect(userCreated.user_email).toBe('trucmuche@opencti');
    expect(userCreated.organizations).toStrictEqual([]);
    await deleteElementById(testContext, authUser, userAddResult.id, ENTITY_TYPE_USER);
  });

  it('should service account user be allowed to be created with a group and one org', async () => {
    const testOrganization: BasicStoreEntityOrganization = await getOrganizationEntity(TEST_ORGANIZATION);
    const testGroup: Group = await getGroupEntity(GREEN_GROUP);

    const userAddInput: UserAddInput = {
      name: 'Service account with group',
      user_service_account: true,
      groups: [testGroup.id],
      objectOrganization: [testOrganization.id],
      prevent_default_groups: true,
    };
    const userAddResult = await addUser(testContext, authUser, userAddInput);
    const userCreated: AuthUser = await findById(testContext, authUser, userAddResult.id);

    expect(userCreated.user_email.endsWith('opencti.invalid'), 'Service account email should be generated').toBeTruthy();
    expect(userCreated.organizations.filter((org) => org.id === testOrganization.id).length, 'Service account user should be created with input org').toBe(1);
    expect(userCreated.organizations.length, 'Input organization should be the only one').toBe(1);
    expect(userCreated.groups.filter((org) => org.id === testGroup.id).length, 'Service account user should be created with input group').toBe(1);
    expect(userCreated.groups.length, 'Input group should be the only one').toBe(1);

    await deleteElementById(testContext, authUser, userAddResult.id, ENTITY_TYPE_USER);
  });

  it('should ThrowError if userAdd not service account, without email', async () => {
    const USER: UserAddInput = {
      name: 'No service account without email',
      user_service_account: false,
      groups: [],
      objectOrganization: [],
    };

    await expect(async () => {
      await addUser(testContext, authUser, USER);
    }).rejects.toThrowError('User cannot be created without email');
  });
  it('should ThrowError if userAdd not service account, without password', async () => {
    const USER: UserAddInput = {
      user_email: 'missingpassword@opencti',
      name: 'No service account without password',
      user_service_account: false,
      groups: [],
      objectOrganization: [],
    };

    await expect(async () => {
      await addUser(testContext, authUser, USER);
    }).rejects.toThrowError('Invalid password: required');
  });
});

describe('Service account with platform organization coverage', async () => {
  const authUser = getFakeAuthUser('Platform administrator');
  authUser.capabilities = [{ name: SETTINGS_SET_ACCESSES }];

  const anotherOrgThanPlatformOne: BasicStoreEntityOrganization = await getOrganizationEntity(TEST_ORGANIZATION);

  beforeAll(async () => {
    // Activate EE for this test
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    await setOrganization(PLATFORM_ORGANIZATION);
  });

  afterAll(async () => {
    // Deactivate EE at the end of this test - back to CE
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockRejectedValue('Enterprise edition is not enabled');
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(false);
    await unSetOrganization();
  });

  it('Standard user should not be added to platform organization', async () => {
    const userAddInput: UserAddInput = {
      user_email: 'user.standard@opencti.fr',
      name: 'Standard user without org',
      user_service_account: false,
      password: 'youWillNeverGuess',
    };
    const userAddResult = await addUser(testContext, authUser, userAddInput);
    const userCreated: AuthUser = await findById(testContext, authUser, userAddResult.id);

    expect(userCreated.organizations, 'This user should be in no organization').toStrictEqual([]);
    await deleteElementById(testContext, authUser, userAddResult.id, ENTITY_TYPE_USER);
  });

  it('Standard user with one org should keep it', async () => {
    const userAddInput: UserAddInput = {
      user_email: 'user.standard@opencti.fr',
      name: 'Standard user without org',
      user_service_account: false,
      password: 'youWillNeverGuess',
      objectOrganization: [anotherOrgThanPlatformOne.id],
    };
    const userAddResult = await addUser(testContext, authUser, userAddInput);
    const userCreated: AuthUser = await findById(testContext, authUser, userAddResult.id);

    expect(userCreated.organizations.filter((org) => org.id === anotherOrgThanPlatformOne.id).length, 'Standard user should be created with organization in input').toBe(1);
    expect(userCreated.organizations.length, 'User organization should be the only one').toBe(1);

    await deleteElementById(testContext, authUser, userAddResult.id, ENTITY_TYPE_USER);
  });
  it('Service account should not store password in DB', async () => {
    const userAddInput: UserAddInput = {
      user_email: 'user.nopassword@opencti.fr',
      name: 'Service account no password',
      user_service_account: true,
      password: 'youWillNeverBeStored',
    };
    const userAddResult = await addUser(testContext, authUser, userAddInput);
    const userCreated: any = await storeLoadById(testContext, authUser, userAddResult.id, ENTITY_TYPE_USER);

    expect(userCreated.password).toBeUndefined();

    await deleteElementById(testContext, authUser, userAddResult.id, ENTITY_TYPE_USER);
  });
  it('Service account should be able to login with token', async () => {
    // GIVEN a service account without any org
    // AND org segregation is activated in policy
    const userAddInput: UserAddInput = {
      user_email: 'token.test@opencti.fr',
      name: 'Service account with token and org',
      user_service_account: true,
    };
    const userAddResult = await addUser(testContext, authUser, userAddInput);
    const userCreated: any = await storeLoadById(testContext, authUser, userAddResult.id, ENTITY_TYPE_USER);
    expect(userCreated.password).toBeUndefined();

    // WHEN user log in with token
    const fakeReq = { headers: () => {
      return undefined;
    }, header: () => {
      return undefined;
    }, socket: { remoteAddress: '::1' } };
    const loggedInUser = await authenticateUserByTokenOrUserId(testContext, fakeReq, userCreated.api_token);
    expect(loggedInUser).toBeDefined();

    await deleteElementById(testContext, authUser, userAddResult.id, ENTITY_TYPE_USER);
  });
});

describe('Testing buildCompleteUser', () => {
  it('should user organization list be composed of organizations entity only', async () => {
    const testOrgCustom = await addOrganization(testContext, ADMIN_USER, { name: 'CompleteUserOrg' });
    const testSector = await addSector(testContext, ADMIN_USER, { name: 'CompleteUserSector' });

    const userInput: UserAddInput = {
      name: `User for buildCompleteUser ${Date.now()}`,
      password: 'buildCompleteUser',
      user_email: 'user.buildCompleteUser@opencti.invalid',
      objectOrganization: [testOrgCustom.id],
    };
    const userInOrgCustom: AuthUser = await addUser(testContext, ADMIN_USER, userInput);
    const wrongRelationInput = { relationship_type: RELATION_PARTICIPATE_TO, toId: testSector.id };
    await userAddRelation(testContext, ADMIN_USER, userInOrgCustom.id, wrongRelationInput);
    const userAuth = await findUserById(testContext, ADMIN_USER, userInOrgCustom.id);
    expect(userAuth.organizations.filter((org: BasicStoreEntity) => org.id === testOrgCustom.id).length).toBe(1); // Actual Organization
    expect(userAuth.organizations.filter((org: BasicStoreEntity) => org.id === testSector.id).length).toBe(0); // Sector should not be there
    expect(userAuth.organizations.length).toBe(1);

    // Cleanup
    await userDelete(testContext, ADMIN_USER, userInOrgCustom.id);
    await deleteElementById(testContext, ADMIN_USER, testOrgCustom.id, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    await deleteElementById(testContext, ADMIN_USER, testSector.id, ENTITY_TYPE_IDENTITY_SECTOR);
  });
});
