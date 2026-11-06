import { afterAll, describe, expect, it } from 'vitest';
import { assembleTemplateData, processNotificationData } from '../../../src/manager/publisherManager';
import { compileTitleVariables, TITLE_VARIABLES_DATA_KEY } from '../../../src/modules/notifier/notifier-title-variables';
import { buildMockNotificationInput, MOCK_NOTIFICATIONS, MOCK_TRIGGERS } from '../../../src/utils/publisher-mock';
import { shutdownSafeEjsPool } from '../../../src/utils/safeEjs.pool';
import { safeRender } from '../../../src/utils/safeEjs.client';
import { sanitizeNotificationData } from '../../../src/utils/templateContextSanitizer';

describe('Test notifier mock data', () => {
  afterAll(async () => {
    await shutdownSafeEjsPool();
  });

  const user = { user_id: 'user-id', user_email: 'user@opencti.io', user_service_account: false, notifiers: [] } as any;
  const usersMap = new Map([['user-id', { id: 'user-id' }]] as any);
  const settings = { platform_title: 'OpenCTI' } as any;
  const EXPECTED_TRIGGER_TYPES: Record<string, string> = {
    default_notification: 'live',
    default_digest: 'digest',
    default_activity: 'live',
  };

  // The very preparation testNotifier does, then the same rendering as the email notifier
  const renderTitle = async (mockId: string, title: string) => {
    const input = buildMockNotificationInput(mockId);
    if (!input) throw new Error(`Unknown mock ${mockId}`);
    const { notificationMap, triggers, notifications } = input;
    const contentEventMapping = await processNotificationData({} as any, notificationMap, user, notifications, usersMap as any);
    const content = Object.entries(contentEventMapping).map(([contentTitle, events]) => ({ title: contentTitle, events }));
    const sanitizedData = sanitizeNotificationData(assembleTemplateData(content, triggers, settings, user, notifications));
    const { template, values } = compileTitleVariables(title, sanitizedData);
    return safeRender(template, { ...sanitizedData, [TITLE_VARIABLES_DATA_KEY]: values }, { usePlainTextEscape: true });
  };

  it('should declare a [TEST] trigger of the expected type for every mock', () => {
    expect(Object.keys(MOCK_TRIGGERS).sort()).toEqual(Object.keys(MOCK_NOTIFICATIONS).sort());
    Object.entries(EXPECTED_TRIGGER_TYPES).forEach(([mockId, triggerType]) => {
      expect(MOCK_TRIGGERS[mockId].trigger_type).toBe(triggerType);
      expect(MOCK_TRIGGERS[mockId].name.startsWith('[TEST]')).toBe(true);
    });
  });

  describe.each(Object.keys(EXPECTED_TRIGGER_TYPES))('%s', (mockId) => {
    it('should fill every part of the documented example title', async () => {
      const rendered = await renderTitle(mockId, '[$notification.name] $notification_content[0].events[0].operation – $notification_content[0].title');
      const match = rendered.match(/^\[(.+)\] (\S+) – (.+)$/);
      expect(match, rendered).not.toBeNull();
      expect(rendered).not.toContain('[]');
      expect(rendered).not.toContain('  ');
      expect(match?.[1]).toBe(MOCK_TRIGGERS[mockId].name);
    });

    it('should expose the trigger type, the instance and the event message', async () => {
      expect(await renderTitle(mockId, '$notification.trigger_type')).toBe(EXPECTED_TRIGGER_TYPES[mockId]);
      expect((await renderTitle(mockId, '$data[0].instance.name')).trim()).not.toBe('');
      expect((await renderTitle(mockId, '$data[0].instance.type')).trim()).not.toBe('');
      expect((await renderTitle(mockId, '$notification_content[0].events[0].message')).trim()).not.toBe('');
    });
  });

  it('should provide two events on two different entities in the digest', async () => {
    expect(await renderTitle('default_digest', '$data.length')).toBe('2');
    const first = await renderTitle('default_digest', '$notification_content[0].title');
    const second = await renderTitle('default_digest', '$notification_content[1].title');
    expect(second.trim()).not.toBe('');
    expect(second).not.toBe(first);
    const firstInstance = await renderTitle('default_digest', '$data[0].instance.name');
    const secondInstance = await renderTitle('default_digest', '$data[1].instance.name');
    expect(secondInstance.trim()).not.toBe('');
    expect(secondInstance).not.toBe(firstInstance);
  });

  it('should not build an input for an unknown or prototype-inherited test id', () => {
    ['unknown', 'constructor', '__proto__', 'toString', 'hasOwnProperty'].forEach((testId) => {
      expect(buildMockNotificationInput(testId)).toBeUndefined();
    });
  });
});
