import { describe, expect, it } from 'vitest';
import { sanitizeNotificationData, sanitizeSettings, sanitizeUser } from '../../../src/utils/templateContextSanitizer';

describe('templateContextSanitizer', () => {
  describe('sanitizeUser', () => {
    const user = {
      name: 'name',
      firstname: 'firstname',
      lastname: 'lastname',
      user_name: 'user_name',
      user_email: 'user_email',
      account_status: 'account_status',
    };

    it('lets pass through a correct user object', () => {
      expect(sanitizeUser(user)).toStrictEqual(user);
    });

    it('lets pass through a user object without an optional field', () => {
      const partialUser = {
        ...user,
      } as Partial<typeof user>;
      delete partialUser.lastname;
      expect(sanitizeUser(partialUser)).toStrictEqual(partialUser);
    });

    it('silently removes extra fields', () => {
      expect(sanitizeUser({
        ...user,
        whatever: 'whatever',
      })).toStrictEqual(user);
    });

    it('strips api_token for security', () => {
      expect(sanitizeUser({
        ...user,
        api_token: 'sensitive-token',
      })).toStrictEqual(user);
    });
  });

  describe('sanitizeSettings', () => {
    const settings = {
      platform_title: 'platform_title',
      platform_email: 'platform_email',
      platform_base_url: 'platform_base_url',
      platform_theme: 'platform_theme',
    };

    it('lets pass through a correct settings object', () => {
      expect(sanitizeSettings(settings)).toStrictEqual(settings);
    });

    it('lets pass through a settings object without an optional field', () => {
      const partialSettings = {
        ...settings,
      } as Partial<typeof settings>;
      delete partialSettings.platform_title;
      expect(sanitizeSettings(partialSettings)).toStrictEqual(partialSettings);
    });

    it('silently removes extra fields', () => {
      expect(sanitizeSettings({
        ...settings,
        whatever: 'whatever',
      })).toStrictEqual(settings);
    });
  });

  describe('sanitizeNotificationData', () => {
    const notificationData = {
      user: {
        name: 'name',
        firstname: 'firstname',
        lastname: 'lastname',
        user_name: 'user_name',
        user_email: 'user_email',
        account_status: 'account_status',
      },
      settings: {
        platform_title: 'platform_title',
        platform_email: 'platform_email',
        platform_base_url: 'platform_base_url',
        platform_theme: 'platform_theme',
      },
      notification: {
        id: 'id',
        name: 'name',
        notification_type: 'notification_type',
        trigger_type: 'trigger_type',
        created: 'created',
      },

      content: [{ content: 'content' }],
      notification_content: [{ notification_content: 'notification_content' }],
      data: [{ data: 'data' }],
      users: [{ users: 'users' }],

      platform_uri: 'platform_uri',
      doc_uri: 'doc_uri',
      background_color: 'background_color',
      url_suffix: 'url_suffix',
      trigger_id: 'trigger_id',
      description: 'description',

      report: { stuff: 'stuff' },

      id: 'id',
      type: 'type',
      name: 'name',
      created: 'created',
      modified: 'modified',
      confidence: 50,
      revoked: false,
      content_field: 'content_field',
      published: 'published',
      labels: ['my-label'],
      report_types: ['report-type'],
    };

    it('lets pass through a correct notificationData object', () => {
      expect(sanitizeNotificationData(notificationData)).toStrictEqual(notificationData);
    });

    it('lets pass through a notificationData object without an optional field', () => {
      const partialNotificationData = {
        ...notificationData,
      } as Partial<typeof notificationData>;
      delete partialNotificationData.confidence;
      delete partialNotificationData.content;
      expect(sanitizeNotificationData(partialNotificationData)).toStrictEqual(partialNotificationData);
    });

    it('silently removes extra fields', () => {
      expect(sanitizeNotificationData({
        ...notificationData,
        whatever: 'whatever',
      })).toStrictEqual(notificationData);
    });
  });
});
