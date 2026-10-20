import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getHttpClient } from '../../../src/utils/http-client';

// WEBHOOK_TIMEOUT is computed once at module import time from conf.get(...), so the override
// must be in place before publisherManager.ts is imported (vi.mock is hoisted above imports).
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: (key: string) => (key === 'publisher_manager:webhook_timeout' ? 9999 : actual.default.get(key)),
    },
  };
});

const { mockedCall } = vi.hoisted(() => ({ mockedCall: vi.fn() }));
vi.mock('../../../src/utils/http-client', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/utils/http-client')>()),
  getHttpClient: vi.fn(() => ({ call: mockedCall })),
}));

// Import after the mock so the module picks up the overridden config value.
const { handleWebhookNotification } = await import('../../../src/manager/publisherManager');

describe('handleWebhookNotification webhook timeout configuration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should use the timeout configured via publisher_manager:webhook_timeout instead of the hardcoded default', async () => {
    const configurationString = JSON.stringify({
      url: 'https://my-webhook-endpoint.com/test',
      verb: 'POST',
      template: '{}',
    });
    mockedCall.mockResolvedValue({ status: 200, data: 'success' });

    await handleWebhookNotification(configurationString, {});

    expect(getHttpClient).toHaveBeenCalledWith(expect.objectContaining({ timeout: 9999 }));
  });

  it('hands the signal of its sending to the webhook call, so that aborting the sending cancels the call', async () => {
    const configurationString = JSON.stringify({ url: 'https://my-webhook-endpoint.com/test', verb: 'POST', template: '{}' });
    mockedAxiosInstance.mockResolvedValue({ status: 200, data: 'success' });
    const sending = new AbortController();

    await handleWebhookNotification(configurationString, {}, sending.signal);

    expect(mockedAxiosInstance).toHaveBeenCalledWith(expect.objectContaining({ url: 'https://my-webhook-endpoint.com/test', signal: sending.signal }));
  });
});
