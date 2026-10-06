import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../src/database/cache';
import { processNotificationEvent } from '../../../src/manager/publisherManager';
import { addNotification } from '../../../src/modules/notification/notification-domain';
import { NOTIFIER_CONNECTOR_UI } from '../../../src/modules/notifier/notifier-statics';

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
  getEntitiesListFromCache: vi.fn(),
  getEntitiesMapFromCache: vi.fn(),
}));

vi.mock('../../../src/modules/notification/notification-domain', () => ({
  addNotification: vi.fn(),
}));

vi.mock('../../../src/manager/telemetryManager', () => ({
  addNotificationSentCount: vi.fn(),
}));

const UI_NOTIFIER_ID = 'ui-notifier-id';
const NOTIFICATION_ID = 'notification-id';

const trigger = { internal_id: NOTIFICATION_ID, id: NOTIFICATION_ID, name: 'My trigger', trigger_type: 'live' };
const user = { user_id: 'user-id', notifiers: [UI_NOTIFIER_ID] } as any;
const notificationMap = new Map([[NOTIFICATION_ID, trigger]] as any);

const runEvent = (notificationData: any[], usersMap: Map<string, any>) => processNotificationEvent(
  {} as any,
  notificationMap as any,
  NOTIFICATION_ID,
  user,
  notificationData,
  usersMap as any,
);

/**
 * The publisher sends notifications fire-and-forget: the stream position advances whether or not
 * the send succeeded. Losing the WRITE of a notification is therefore unrecoverable and someone
 * has to act on it, while a remote notifier or a user's configuration failing is not. Both land in
 * the same `.catch`, so these tests pin that the two are told apart — and told apart by WHERE the
 * failure happened, not by the notifier's type: both cases below use the same UI notifier.
 */
describe('Publisher manager notification failure severity', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (getEntityFromCache as any).mockResolvedValue({});
    (getEntitiesListFromCache as any).mockResolvedValue([
      { internal_id: UI_NOTIFIER_ID, notifier_connector_id: NOTIFIER_CONNECTOR_UI },
    ]);
  });

  it('should report a failed notification write as an error', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    (addNotification as any).mockRejectedValue(new Error('elastic is down'));

    // No notification data, so nothing can fail before the write itself.
    await runEvent([], new Map());

    // The catch is detached from the call on purpose, so let it settle before asserting.
    await vi.waitFor(() => expect(logAppErrorSpy).toHaveBeenCalledTimes(1));
    expect(logAppErrorSpy.mock.calls[0][0]).toContain('notification write failed');
    expect(logAppWarnSpy, 'A lost write is not a warning.').not.toHaveBeenCalled();
  });

  it('should report a failure raised before the write as a warning, on the same UI notifier', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    (addNotification as any).mockResolvedValue(undefined);

    // processNotificationData throws for a user missing from the map, before any write is attempted.
    const notificationData = [{
      notification_id: NOTIFICATION_ID,
      instance: { id: 'instance-id', entity_type: 'Report' },
      type: 'create',
      message: 'a message',
    }];
    await runEvent(notificationData, new Map());

    await vi.waitFor(() => expect(logAppWarnSpy).toHaveBeenCalledTimes(1));
    expect(logAppWarnSpy.mock.calls[0][0]).toContain('notification processing error');
    expect(addNotification, 'Nothing should have been written.').not.toHaveBeenCalled();
    expect(logAppErrorSpy, 'Testing the notifier type alone would have got this one wrong.').not.toHaveBeenCalled();
  });

  it('should log nothing when the notification is written', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    (addNotification as any).mockResolvedValue(undefined);

    await runEvent([], new Map());

    await vi.waitFor(() => expect(addNotification).toHaveBeenCalledTimes(1));
    expect(logAppErrorSpy).not.toHaveBeenCalled();
    expect(logAppWarnSpy).not.toHaveBeenCalled();
  });
});
