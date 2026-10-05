import { afterEach, describe, expect, it, vi } from 'vitest';

// The delivery receipts, kept in memory (no Redis needed): claimed while a notifier sends, delivered once it succeeded.
const receipts = vi.hoisted(() => new Map<string, 'claimed' | 'delivered'>());
vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisClaimDigestDelivery: async (receipt: string) => {
    if (receipts.has(receipt)) return false;
    receipts.set(receipt, 'claimed');
    return true;
  },
  redisConfirmDigestDelivery: async (receipt: string) => {
    receipts.set(receipt, 'delivered');
  },
  redisReleaseDigestDelivery: async (receipt: string) => {
    receipts.delete(receipt);
  },
}));

import { sendToNotifier } from '../../../src/manager/publisherManager';

const EMAIL_RECEIPT = 'change-digest-1|analyst-1|2026-01-05T09:00:00.000Z|2026-01-12T09:00:00.000Z|notifier-email';
const UI_RECEIPT = 'change-digest-1|analyst-1|2026-01-05T09:00:00.000Z|2026-01-12T09:00:00.000Z|notifier-ui';

describe('Digest delivery through a notifier', () => {
  afterEach(() => {
    receipts.clear();
  });

  it('sends a digest stored twice once per notifier, even while the first sending is in progress', async () => {
    let finish: () => void = () => {};
    const sending = new Promise<void>((resolve) => {
      finish = resolve;
    });
    const send = vi.fn().mockReturnValueOnce(sending).mockResolvedValue(undefined);
    const first = sendToNotifier(EMAIL_RECEIPT, send);
    // The second copy arrives while the notifier still sends the first one
    expect(await sendToNotifier(EMAIL_RECEIPT, send)).toBe(false);
    finish();
    expect(await first).toBe(true);
    expect(receipts.get(EMAIL_RECEIPT)).toBe('delivered');
    expect(await sendToNotifier(EMAIL_RECEIPT, send)).toBe(false);
    // Another notifier of the same digest has its own receipt
    expect(await sendToNotifier(UI_RECEIPT, send)).toBe(true);
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('keeps the receipt only once the notifier succeeded, so a failed sending is sent again', async () => {
    const send = vi.fn().mockRejectedValueOnce(new Error('smtp unavailable')).mockResolvedValueOnce(undefined);
    await expect(sendToNotifier(EMAIL_RECEIPT, send)).rejects.toThrow('smtp unavailable');
    expect(receipts.has(EMAIL_RECEIPT)).toBe(false);
    expect(await sendToNotifier(EMAIL_RECEIPT, send)).toBe(true);
    expect(receipts.get(EMAIL_RECEIPT)).toBe('delivered');
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('always sends the notifications without receipt', async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    expect(await sendToNotifier(undefined, send)).toBe(true);
    expect(await sendToNotifier(undefined, send)).toBe(true);
    expect(send).toHaveBeenCalledTimes(2);
    expect(receipts.size).toBe(0);
  });
});
