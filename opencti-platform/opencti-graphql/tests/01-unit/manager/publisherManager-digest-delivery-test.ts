import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DigestEvent } from '../../../src/manager/notificationManager';

// The delivery receipts, kept in memory (no Redis needed).
const deliveries = vi.hoisted(() => new Set<string>());
vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisIsDigestDelivered: async (deliveryKey: string) => deliveries.has(deliveryKey),
  redisMarkDigestDelivered: async (deliveryKey: string) => {
    deliveries.add(deliveryKey);
  },
}));

import { deliverDigestOnce } from '../../../src/manager/publisherManager';

const digestEvent = (deliveryKey?: string) => ({
  version: '1',
  type: 'digest',
  notification_id: 'change-digest-1',
  target: { user_id: 'analyst-1', user_email: 'analyst@local', notifiers: ['notifier-ui'], user_service_account: false },
  data: [],
  ...(deliveryKey ? { delivery_key: deliveryKey } : {}),
} as unknown as DigestEvent);

describe('Digest delivery', () => {
  afterEach(() => {
    deliveries.clear();
  });

  it('delivers a digest stored twice under the same delivery key once', async () => {
    const deliver = vi.fn().mockResolvedValue(undefined);
    expect(await deliverDigestOnce(digestEvent('change-digest-1|analyst-1|from|to'), deliver)).toBe(true);
    expect(await deliverDigestOnce(digestEvent('change-digest-1|analyst-1|from|to'), deliver)).toBe(false);
    expect(await deliverDigestOnce(digestEvent('change-digest-1|analyst-1|to|next'), deliver)).toBe(true);
    expect(deliver).toHaveBeenCalledTimes(2);
  });

  it('records the delivery only once the digest is delivered, so a failed delivery is tried again', async () => {
    const deliver = vi.fn().mockRejectedValueOnce(new Error('smtp unavailable')).mockResolvedValueOnce(undefined);
    await expect(deliverDigestOnce(digestEvent('change-digest-1|analyst-1|from|to'), deliver)).rejects.toThrow('smtp unavailable');
    expect(deliveries.size).toBe(0);
    expect(await deliverDigestOnce(digestEvent('change-digest-1|analyst-1|from|to'), deliver)).toBe(true);
    expect(deliver).toHaveBeenCalledTimes(2);
  });

  it('always delivers the digests without delivery key', async () => {
    const deliver = vi.fn().mockResolvedValue(undefined);
    await deliverDigestOnce(digestEvent(), deliver);
    await deliverDigestOnce(digestEvent(), deliver);
    expect(deliver).toHaveBeenCalledTimes(2);
    expect(deliveries.size).toBe(0);
  });
});
