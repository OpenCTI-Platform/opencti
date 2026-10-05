import { afterEach, describe, expect, it, vi } from 'vitest';

// The delivery receipts, kept in memory (no Redis needed): claimed by an owner while a notifier sends, delivered once
// it succeeded. Only the owner of a claim renews, confirms or releases it.
const receipts = vi.hoisted(() => new Map<string, { state: 'claimed' | 'delivered'; owner?: string }>());
const renewals = vi.hoisted(() => [] as string[]);
vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisClaimDigestDelivery: async (receipt: string, owner: string) => {
    if (receipts.has(receipt)) return false;
    receipts.set(receipt, { state: 'claimed', owner });
    return true;
  },
  redisRenewDigestDelivery: async (receipt: string, owner: string) => {
    renewals.push(owner);
    return receipts.get(receipt)?.owner === owner;
  },
  redisConfirmDigestDelivery: async (receipt: string, owner: string) => {
    if (receipts.get(receipt)?.owner !== owner) return false;
    receipts.set(receipt, { state: 'delivered' });
    return true;
  },
  redisReleaseDigestDelivery: async (receipt: string, owner: string) => {
    if (receipts.get(receipt)?.owner !== owner) return false;
    receipts.delete(receipt);
    return true;
  },
}));

import { sendToNotifier } from '../../../src/manager/publisherManager';
import { DIGEST_DELIVERY_RENEW_MS } from '../../../src/database/redis';

const EMAIL_RECEIPT = 'change-digest-1|analyst-1|2026-01-05T09:00:00.000Z|2026-01-12T09:00:00.000Z|notifier-email';
const UI_RECEIPT = 'change-digest-1|analyst-1|2026-01-05T09:00:00.000Z|2026-01-12T09:00:00.000Z|notifier-ui';

describe('Digest delivery through a notifier', () => {
  afterEach(() => {
    receipts.clear();
    renewals.splice(0);
    vi.useRealTimers();
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
    expect(receipts.get(EMAIL_RECEIPT)?.state).toBe('delivered');
    expect(await sendToNotifier(EMAIL_RECEIPT, send)).toBe(false);
    // Another notifier of the same digest has its own receipt
    expect(await sendToNotifier(UI_RECEIPT, send)).toBe(true);
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('renews the claim with its owner token while the notifier sends, and stops once it is done', async () => {
    vi.useFakeTimers();
    let finish: () => void = () => {};
    const send = vi.fn().mockReturnValue(new Promise<void>((resolve) => {
      finish = resolve;
    }));
    const sent = sendToNotifier(EMAIL_RECEIPT, send);
    await vi.advanceTimersByTimeAsync(DIGEST_DELIVERY_RENEW_MS * 3);
    const owner = receipts.get(EMAIL_RECEIPT)?.owner;
    expect(renewals).toEqual([owner, owner, owner]);
    finish();
    expect(await sent).toBe(true);
    await vi.advanceTimersByTimeAsync(DIGEST_DELIVERY_RENEW_MS * 2);
    expect(renewals).toHaveLength(3);
    expect(receipts.get(EMAIL_RECEIPT)?.state).toBe('delivered');
  });

  it('never confirms or releases the claim of another owner', async () => {
    let finish: () => void = () => {};
    const send = vi.fn().mockReturnValue(new Promise<void>((resolve) => {
      finish = resolve;
    }));
    const sent = sendToNotifier(EMAIL_RECEIPT, send);
    await vi.waitFor(() => expect(send).toHaveBeenCalled());
    // The claim expired and another sender took it meanwhile
    receipts.set(EMAIL_RECEIPT, { state: 'claimed', owner: 'other-sender' });
    finish();
    expect(await sent).toBe(true);
    expect(receipts.get(EMAIL_RECEIPT)).toEqual({ state: 'claimed', owner: 'other-sender' });
  });

  it('keeps the receipt only once the notifier succeeded, so a failed sending is sent again', async () => {
    const send = vi.fn().mockRejectedValueOnce(new Error('smtp unavailable')).mockResolvedValueOnce(undefined);
    await expect(sendToNotifier(EMAIL_RECEIPT, send)).rejects.toThrow('smtp unavailable');
    expect(receipts.has(EMAIL_RECEIPT)).toBe(false);
    expect(await sendToNotifier(EMAIL_RECEIPT, send)).toBe(true);
    expect(receipts.get(EMAIL_RECEIPT)?.state).toBe('delivered');
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
