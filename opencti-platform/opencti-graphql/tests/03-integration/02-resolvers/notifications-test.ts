import { beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getAuthUser, testContext, USER_EDITOR } from '../../utils/testQuery';
import { addNotification } from '../../../src/modules/notification/notification-domain';
import { adminQueryWithSuccess, queryAsUserIsExpectedError, queryAsUserWithSuccess } from '../../utils/testQueryHelper';

const READ_NOTIFICATION_QUERY = gql`
  query notification($id: String!) {
    notification(id: $id) {
      id
      name
    }
  }
`;
const DELETE_NOTIFICATION_QUERY = gql`
  mutation NotificationDelete($id: ID!) {
    notificationDelete(id: $id)
  }
`;
const MARK_READ_NOTIFICATION_QUERY = gql`
  mutation NotificationMarkRead($id: ID!, $read: Boolean!) {
    notificationMarkRead(id: $id, read: $read) {
      is_read
    }
  }
`;

describe('Notifications resolver restriction behavior', () => {
  let adminNotificationId: string;
  let userNotificationId: string;
  beforeAll(async () => {
    // Admin creates 1 notification
    const adminNotificationInput = {
      is_read: false,
      name: 'Admin notification',
      notification_type: 'live',
      notification_content: [
        {
          title: 'report same org intersec',
          events: [
            {
              operation: 'update',
              message: '[report] report same org intersec - `admin` replaces `description updated` in `Description`',
              instance_id: 'report--b07ba95d-8a26-59c9-91a0-54a0829eae09'
            }
          ]
        }
      ],
      user_id: ADMIN_USER.id
    };

    const adminNotification = await addNotification(testContext, ADMIN_USER, adminNotificationInput);
    adminNotificationId = adminNotification.id;

    // User creates 1 notification
    const user = await getAuthUser(USER_EDITOR.id);
    const userNotificationInput = {
      is_read: false,
      name: 'User notification',
      notification_type: 'live',
      notification_content: [
        {
          title: 'report same org intersec',
          events: [
            {
              operation: 'update',
              message: '[report] report same org intersec - `admin` replaces `description updated` in `Description`',
              instance_id: 'report--b07ba95d-8a26-59c9-91a0-54a0829eae09'
            }
          ]
        }
      ],
      user_id: user.id
    };
    const userNotification = await addNotification(testContext, user, userNotificationInput);
    userNotificationId = userNotification.id;
  });

  it('Admin user should get its own notification', async () => {
    const result = await adminQueryWithSuccess({
      query: READ_NOTIFICATION_QUERY,
      variables: {
        id: adminNotificationId
      }
    });
    expect(result.data.notification.id).toEqual(adminNotificationId);
  });
  it('Admin user should get user notification', async () => {
    const result = await adminQueryWithSuccess({
      query: READ_NOTIFICATION_QUERY,
      variables: {
        id: userNotificationId
      }
    });
    expect(result.data.notification.id).toEqual(userNotificationId);
  });
  it('User should get its own notification', async () => {
    const result = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: READ_NOTIFICATION_QUERY,
      variables: {
        id: userNotificationId
      }
    });
    expect(result.data.notification.id).toEqual(userNotificationId);
  });
  it('User should not get Admin notification', async () => {
    const result = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: READ_NOTIFICATION_QUERY,
      variables: {
        id: adminNotificationId
      }
    });
    expect(result.data.notification).toBeNull();
  });
  it('User should not update Admin notification', async () => {
    await queryAsUserIsExpectedError(USER_EDITOR.client, {
      query: MARK_READ_NOTIFICATION_QUERY,
      variables: {
        id: adminNotificationId,
        read: true,
      },
    }, 'Cant find element to update', 'FUNCTIONAL_ERROR');
  });
  it('User should not delete Admin notification', async () => {
    await queryAsUserIsExpectedError(USER_EDITOR.client, {
      query: DELETE_NOTIFICATION_QUERY,
      variables: {
        id: adminNotificationId,
        read: true,
      },
    }, 'Already deleted elements', 'ALREADY_DELETED_ERROR');
  });
  it('Admin should delete User notification', async () => {
    await adminQueryWithSuccess({
      query: DELETE_NOTIFICATION_QUERY,
      variables: {
        id: userNotificationId
      }
    });
    const result = await adminQueryWithSuccess({
      query: READ_NOTIFICATION_QUERY,
      variables: {
        id: userNotificationId
      }
    });
    expect(result.data.notification).toBeNull();
  });
  it('Admin should delete its own notification', async () => {
    await adminQueryWithSuccess({
      query: DELETE_NOTIFICATION_QUERY,
      variables: {
        id: adminNotificationId
      }
    });
    const result = await adminQueryWithSuccess({
      query: READ_NOTIFICATION_QUERY,
      variables: {
        id: userNotificationId
      }
    });
    expect(result.data.notification).toBeNull();
  });
});
