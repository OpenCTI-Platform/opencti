import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { getEntitiesListFromCache, getEntitiesMapFromCache, getEntityFromCache } from '../../../src/database/cache';
import { sendMail } from '../../../src/database/smtp';
import { processNotificationEvent } from '../../../src/manager/publisherManager';
import type { NotificationUser } from '../../../src/manager/notificationManager';
import type { BasicStoreEntityTrigger } from '../../../src/modules/notification/notification-types';
import type { BasicStoreEntityNotifier } from '../../../src/modules/notifier/notifier-types';
import { NOTIFIER_CONNECTOR_EMAIL } from '../../../src/modules/notifier/notifier-statics';
import type { BasicStoreSettings } from '../../../src/types/settings';
import type { AuthContext, AuthUser } from '../../../src/types/user';

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
  getEntitiesListFromCache: vi.fn(),
  getEntitiesMapFromCache: vi.fn(),
}));

vi.mock('../../../src/database/smtp', () => ({
  sendMail: vi.fn(),
  smtpComputeFrom: vi.fn(async () => 'platform@opencti.io'),
  smtpIsAlive: vi.fn(),
}));

vi.mock('../../../src/utils/safeEjs.client', () => ({
  safeRender: vi.fn(async () => 'rendered'),
}));

vi.mock('../../../src/manager/telemetryManager', () => ({
  addNotificationSentCount: vi.fn(),
}));

interface SmtpError extends Error {
  code: string;
}

const EMAIL_NOTIFIER_ID = 'email-notifier-id';
const TRIGGER_ID = 'trigger-id';
const SUMMARY_INTERVAL_MS = 60000;

const trigger = { internal_id: TRIGGER_ID, id: TRIGGER_ID, name: 'My trigger', trigger_type: 'live' } as BasicStoreEntityTrigger;
const emailNotifier = { internal_id: EMAIL_NOTIFIER_ID, notifier_connector_id: NOTIFIER_CONNECTOR_EMAIL, notifier_configuration: '{}' } as BasicStoreEntityNotifier;
const user: NotificationUser = { user_id: 'user-id', user_email: 'user@opencti.io', notifiers: [EMAIL_NOTIFIER_ID], user_service_account: false };

const smtpError = (code: string): SmtpError => Object.assign(new Error(`smtp ${code}`), { code });

const runEmailEvent = () => processNotificationEvent(
  {} as AuthContext,
  new Map([[TRIGGER_ID, trigger]]),
  TRIGGER_ID,
  user,
  [],
  new Map<string, AuthUser>(),
);

describe('Publisher manager email notification failure log', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    vi.mocked(getEntityFromCache).mockResolvedValue({} as BasicStoreSettings);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([emailNotifier]);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map());
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should log failed email notifications once per minute, counted by error code, instead of once per email', async () => {
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    vi.mocked(sendMail)
      .mockRejectedValueOnce(smtpError('ETIMEDOUT'))
      .mockRejectedValueOnce(smtpError('ETIMEDOUT'))
      .mockRejectedValueOnce(new Error('no code'));

    await runEmailEvent();
    await runEmailEvent();
    await runEmailEvent();
    await vi.advanceTimersByTimeAsync(SUMMARY_INTERVAL_MS - 1);
    expect(sendMail).toHaveBeenCalledTimes(3);
    expect(logAppWarnSpy).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(logAppWarnSpy).toHaveBeenCalledTimes(1);
    expect(logAppWarnSpy.mock.calls[0][1]).toMatchObject({ failures: { ETIMEDOUT: 2, UNKNOWN: 1 }, triggerCount: 1 });
  });

  it('should start a new summary after the previous one was logged', async () => {
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    vi.mocked(sendMail).mockRejectedValue(smtpError('EAUTH'));

    await runEmailEvent();
    await vi.advanceTimersByTimeAsync(SUMMARY_INTERVAL_MS);
    await runEmailEvent();
    await vi.advanceTimersByTimeAsync(SUMMARY_INTERVAL_MS);

    expect(logAppWarnSpy).toHaveBeenCalledTimes(2);
    expect(logAppWarnSpy.mock.calls[1][1]).toMatchObject({ failures: { EAUTH: 1 } });
  });
});
