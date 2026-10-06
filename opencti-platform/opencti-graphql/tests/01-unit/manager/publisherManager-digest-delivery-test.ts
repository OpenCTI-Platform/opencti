import { afterEach, describe, expect, it, vi } from 'vitest';

// The delivery receipts, kept in memory (no Redis needed): claimed by an owner while a notifier sends, delivered once
// it succeeded. Only the owner of a claim renews or releases it; a delivery is recorded whoever holds the claim.
const receipts = vi.hoisted(() => new Map<string, { state: 'claimed' | 'delivered'; owner?: string }>());
const renewals = vi.hoisted(() => [] as string[]);
const redisFailures = vi.hoisted(() => ({ renew: 0, confirm: 0 }));
vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisClaimDigestDelivery: async (receipt: string, owner: string) => {
    const current = receipts.get(receipt);
    if (current) return current.state === 'delivered' ? 'delivered' : 'claimed_by_another_owner';
    receipts.set(receipt, { state: 'claimed', owner });
    return 'claimed';
  },
  redisRenewDigestDelivery: async (receipt: string, owner: string) => {
    renewals.push(owner);
    if (redisFailures.renew > 0) {
      redisFailures.renew -= 1;
      throw new Error('redis unavailable');
    }
    return receipts.get(receipt)?.owner === owner;
  },
  redisConfirmDigestDelivery: async (receipt: string, owner: string) => {
    if (redisFailures.confirm > 0) {
      redisFailures.confirm -= 1;
      throw new Error('redis unavailable');
    }
    const current = receipts.get(receipt);
    receipts.set(receipt, { state: 'delivered' });
    if (current?.owner === owner) return 'confirmed';
    return current ? 'claim_taken' : 'claim_lost';
  },
  redisReleaseDigestDelivery: async (receipt: string, owner: string) => {
    if (receipts.get(receipt)?.owner !== owner) return false;
    receipts.delete(receipt);
    return true;
  },
}));

// No platform cache here: the markings a notification resolves for its templates are read from an empty one.
vi.mock('../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/cache')>()),
  getEntitiesMapFromCache: async () => new Map(),
}));

const addNotificationMock = vi.hoisted(() => vi.fn());
vi.mock('../../../src/modules/notification/notification-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/notification/notification-domain')>()),
  addNotification: addNotificationMock,
}));

import { internalProcessNotification, sendToNotifier } from '../../../src/manager/publisherManager';
import { DIGEST_DELIVERY_RENEW_MS } from '../../../src/database/digest-delivery-timing';
import { NOTIFIER_CONNECTOR_UI } from '../../../src/modules/notifier/notifier-statics';
import type { AuthContext } from '../../../src/types/user';
import type { BasicStoreSettings } from '../../../src/types/settings';
import type { BasicStoreEntityTrigger } from '../../../src/modules/notification/notification-types';
import type { BasicStoreEntityNotifier } from '../../../src/modules/notifier/notifier-types';

const EMAIL_RECEIPT = 'change-digest-1|analyst-1|2026-01-05T09:00:00.000Z|2026-01-12T09:00:00.000Z|notifier-email';
const UI_RECEIPT = 'change-digest-1|analyst-1|2026-01-05T09:00:00.000Z|2026-01-12T09:00:00.000Z|notifier-ui';

// A notifier that sends until `finish` is called; `honourAbort` makes it stop when its sending is aborted, like a webhook
const pendingNotifier = (honourAbort: boolean) => {
  const control = { finish: () => {}, signal: undefined as AbortSignal | undefined };
  const send = vi.fn((signal: AbortSignal) => new Promise<void>((resolve, reject) => {
    control.signal = signal;
    control.finish = resolve;
    if (honourAbort) signal.addEventListener('abort', () => reject(signal.reason));
  }));
  return { send, control };
};

describe('Digest delivery through a notifier', () => {
  afterEach(() => {
    receipts.clear();
    renewals.splice(0);
    redisFailures.renew = 0;
    redisFailures.confirm = 0;
    vi.useRealTimers();
  });

  it('sends a digest stored twice once per notifier, even while the first sending is in progress', async () => {
    const { send, control } = pendingNotifier(false);
    const first = sendToNotifier(EMAIL_RECEIPT, send);
    await vi.waitFor(() => expect(send).toHaveBeenCalled());
    // The second copy arrives while the notifier still sends the first one
    expect(await sendToNotifier(EMAIL_RECEIPT, send)).toBe('being_sent');
    control.finish();
    expect(await first).toBe('sent');
    expect(receipts.get(EMAIL_RECEIPT)?.state).toBe('delivered');
    expect(await sendToNotifier(EMAIL_RECEIPT, send)).toBe('already_sent');
    // Another notifier of the same digest has its own receipt
    send.mockResolvedValueOnce(undefined);
    expect(await sendToNotifier(UI_RECEIPT, send)).toBe('sent');
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('renews the claim with its owner token while the notifier sends, and stops once it is done', async () => {
    vi.useFakeTimers();
    const { send, control } = pendingNotifier(false);
    const sent = sendToNotifier(EMAIL_RECEIPT, send);
    await vi.advanceTimersByTimeAsync(DIGEST_DELIVERY_RENEW_MS * 3);
    const owner = receipts.get(EMAIL_RECEIPT)?.owner;
    expect(renewals).toEqual([owner, owner, owner]);
    expect(control.signal?.aborted).toBe(false);
    control.finish();
    expect(await sent).toBe('sent');
    await vi.advanceTimersByTimeAsync(DIGEST_DELIVERY_RENEW_MS * 2);
    expect(renewals).toHaveLength(3);
    expect(receipts.get(EMAIL_RECEIPT)?.state).toBe('delivered');
  });

  it('aborts the sending as soon as another sender took the claim, and leaves the claim to it', async () => {
    vi.useFakeTimers();
    const { send, control } = pendingNotifier(true);
    const sent = sendToNotifier(EMAIL_RECEIPT, send);
    const outcome = expect(sent).rejects.toThrow('Digest delivery claim lost');
    await vi.waitFor(() => expect(send).toHaveBeenCalled());
    receipts.set(EMAIL_RECEIPT, { state: 'claimed', owner: 'other-sender' });
    await vi.advanceTimersByTimeAsync(DIGEST_DELIVERY_RENEW_MS);
    expect(control.signal?.aborted).toBe(true);
    await outcome;
    expect(receipts.get(EMAIL_RECEIPT)).toEqual({ state: 'claimed', owner: 'other-sender' });
    // No renewal of a lost claim
    await vi.advanceTimersByTimeAsync(DIGEST_DELIVERY_RENEW_MS * 2);
    expect(renewals).toHaveLength(1);
  });

  it('aborts the sending before the claim can lapse when it cannot be renewed, and keeps renewing until the notifier stops', async () => {
    vi.useFakeTimers();
    redisFailures.renew = 3;
    const { send, control } = pendingNotifier(false);
    const sent = sendToNotifier(EMAIL_RECEIPT, send);
    // Two failed renewals leave more than a renewal period of claim
    await vi.advanceTimersByTimeAsync(DIGEST_DELIVERY_RENEW_MS * 2);
    expect(control.signal?.aborted).toBe(false);
    // The third one leaves less: the sending is aborted, one renewal period before the claim lapses
    await vi.advanceTimersByTimeAsync(DIGEST_DELIVERY_RENEW_MS);
    expect(control.signal?.aborted).toBe(true);
    // An email already handed to its server finishes: its claim is still renewed and its delivery recorded
    await vi.advanceTimersByTimeAsync(DIGEST_DELIVERY_RENEW_MS);
    expect(renewals).toHaveLength(4);
    control.finish();
    expect(await sent).toBe('sent');
    expect(receipts.get(EMAIL_RECEIPT)?.state).toBe('delivered');
  });

  it('records a sending that ended after another sender took the claim, and reports it as possibly sent twice', async () => {
    const { send, control } = pendingNotifier(false);
    const sent = sendToNotifier(EMAIL_RECEIPT, send);
    await vi.waitFor(() => expect(send).toHaveBeenCalled());
    receipts.set(EMAIL_RECEIPT, { state: 'claimed', owner: 'other-sender' });
    control.finish();
    expect(await sent).toBe('possibly_sent_twice');
    // Recorded, so no later copy reaches this notifier
    expect(receipts.get(EMAIL_RECEIPT)?.state).toBe('delivered');
    expect(await sendToNotifier(EMAIL_RECEIPT, send)).toBe('already_sent');
  });

  it('records a sending whose claim was lost when nobody else took it', async () => {
    const { send, control } = pendingNotifier(false);
    const sent = sendToNotifier(EMAIL_RECEIPT, send);
    await vi.waitFor(() => expect(send).toHaveBeenCalled());
    receipts.delete(EMAIL_RECEIPT);
    control.finish();
    expect(await sent).toBe('sent');
    expect(receipts.get(EMAIL_RECEIPT)?.state).toBe('delivered');
  });

  it('tries to record a delivery again while its claim holds', async () => {
    vi.useFakeTimers();
    redisFailures.confirm = 2;
    const send = vi.fn().mockResolvedValue(undefined);
    const sent = sendToNotifier(EMAIL_RECEIPT, send);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(await sent).toBe('sent');
    expect(receipts.get(EMAIL_RECEIPT)?.state).toBe('delivered');
  });

  it('keeps the receipt only once the notifier succeeded, so a failed sending is sent again', async () => {
    const send = vi.fn().mockRejectedValueOnce(new Error('smtp unavailable')).mockResolvedValueOnce(undefined);
    await expect(sendToNotifier(EMAIL_RECEIPT, send)).rejects.toThrow('smtp unavailable');
    expect(receipts.has(EMAIL_RECEIPT)).toBe(false);
    expect(await sendToNotifier(EMAIL_RECEIPT, send)).toBe('sent');
    expect(receipts.get(EMAIL_RECEIPT)?.state).toBe('delivered');
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('always sends the notifications without receipt', async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    expect(await sendToNotifier(undefined, send)).toBe('sent');
    expect(await sendToNotifier(undefined, send)).toBe('sent');
    expect(send).toHaveBeenCalledTimes(2);
    expect(receipts.size).toBe(0);
  });

  it('does not hand a notification over to its notifier once its sending is aborted', async () => {
    const sending = new AbortController();
    sending.abort(new Error('Digest delivery claim lost'));
    const user = { user_id: 'analyst-1', user_email: 'analyst-1@local', user_service_account: false, notifiers: ['notifier-ui'] };
    const notifier = { notifier_connector_id: NOTIFIER_CONNECTOR_UI } as BasicStoreEntityNotifier;
    const trigger = { id: 'change-digest-1', name: 'Weekly landscape', trigger_type: 'change_digest' } as BasicStoreEntityTrigger;
    const processing = internalProcessNotification({} as AuthContext, {} as BasicStoreSettings, new Map(), user, notifier, [], [trigger], new Map(), sending.signal);
    await expect(processing).rejects.toThrow('Digest delivery claim lost');
    expect(addNotificationMock).not.toHaveBeenCalled();
  });
});
