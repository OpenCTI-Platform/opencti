import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesMapFromCache } from '../../../src/database/cache';
import { internalProcessNotification } from '../../../src/manager/publisherManager';
import { addNotification } from '../../../src/modules/notification/notification-domain';
import { NOTIFIER_CONNECTOR_EMAIL, NOTIFIER_CONNECTOR_UI, NOTIFIER_CONNECTOR_WEBHOOK } from '../../../src/modules/notifier/notifier-statics';

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

const { mockedCall } = vi.hoisted(() => ({ mockedCall: vi.fn() }));
vi.mock('../../../src/utils/http-client', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/utils/http-client')>()),
  getHttpClient: vi.fn(() => ({ call: mockedCall })),
}));

const trigger = { internal_id: 'trigger-id', id: 'trigger-id', name: 'XTM One - fleet - reports', trigger_type: 'live' } as any;
const serviceAccount = { user_id: 'service-id', user_email: '', notifiers: [], user_service_account: true } as any;

const notifierOf = (connectorId: string) => ({
  notifier_connector_id: connectorId,
  notifier_configuration: JSON.stringify({ url: 'https://receiver.example/hook', verb: 'POST', template: '{}' }),
}) as any;

const run = (notifier: any) => internalProcessNotification(
  {} as any,
  {} as any,
  new Map([['trigger-id', trigger]]),
  serviceAccount,
  notifier,
  [],
  [trigger],
  new Map(),
);

/**
 * A service account has no mailbox and no UI, but it is the identity a machine (an automation
 * platform) uses to subscribe to OpenCTI events: a webhook notifier must deliver to it, every
 * other notifier is skipped without raising.
 */
describe('Publisher manager notifications for a service account', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (getEntitiesMapFromCache as any).mockResolvedValue(new Map());
    mockedCall.mockResolvedValue({ status: 200, data: 'ok' });
  });

  it('should deliver through a webhook notifier', async () => {
    await run(notifierOf(NOTIFIER_CONNECTOR_WEBHOOK));
    expect(mockedCall).toHaveBeenCalledTimes(1);
  });

  it('should skip a UI notifier without raising', async () => {
    await expect(run(notifierOf(NOTIFIER_CONNECTOR_UI))).resolves.toBeUndefined();
    expect(addNotification).not.toHaveBeenCalled();
    expect(mockedCall).not.toHaveBeenCalled();
  });

  it('should skip an email notifier without raising', async () => {
    await expect(run(notifierOf(NOTIFIER_CONNECTOR_EMAIL))).resolves.toBeUndefined();
    expect(mockedCall).not.toHaveBeenCalled();
  });
});
