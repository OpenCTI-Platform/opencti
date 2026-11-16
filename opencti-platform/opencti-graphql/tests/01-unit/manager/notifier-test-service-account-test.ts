import { describe, expect, it, vi } from 'vitest';
import { internalProcessNotification } from '../../../src/manager/publisherManager';
import { testNotifier } from '../../../src/modules/notifier/notifier-domain';
import { NOTIFIER_CONNECTOR_WEBHOOK } from '../../../src/modules/notifier/notifier-statics';

vi.mock('../../../src/manager/publisherManager', () => ({
  internalProcessNotification: vi.fn(),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
  getEntitiesListFromCache: vi.fn(),
  getEntitiesMapFromCache: vi.fn(),
}));

describe('testNotifier with a service account', () => {
  it('refuses the test without issuing any request', async () => {
    const user = { id: 'service', user_email: 'service@local', user_service_account: true } as any;
    const notifier = {
      name: 'webhook',
      notifier_connector_id: NOTIFIER_CONNECTOR_WEBHOOK,
      notifier_configuration: JSON.stringify({ url: 'http://127.0.0.1', verb: 'POST', template: '{}' }),
      notifier_test_id: 'default_notification_id',
    } as any;
    const result = await testNotifier({} as any, user, notifier);
    expect(result).toBe('Cannot test a notifier with a service account');
    expect(internalProcessNotification).not.toHaveBeenCalled();
  });
});
