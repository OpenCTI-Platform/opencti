import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return {
    ...actual,
    logApp: { info: vi.fn(), error: vi.fn(), debug: vi.fn(), warn: vi.fn() },
  };
});
vi.mock('../../../src/database/redis', () => ({ pubSubAsyncIterator: vi.fn() }));
vi.mock('../../../src/database/middleware-loader', () => ({ internalLoadById: vi.fn() }));
vi.mock('../../../src/database/cache', () => ({ getEntityFromCache: vi.fn() }));

import { logApp } from '../../../src/config/conf';
import { pubSubAsyncIterator } from '../../../src/database/redis';
import { internalLoadById } from '../../../src/database/middleware-loader';
import { subscribeToInstanceEvents } from '../../../src/graphql/subscriptionWrapper';

const INSTANCE_ID = 'instance-id';
const TOPIC = 'TEST_EDIT_TOPIC';
const context = { user: { id: 'subscriber-id' } };

const buildSourceIterator = () => ({
  next: vi.fn(() => new Promise<IteratorResult<unknown>>(() => {})),
  return: vi.fn(async () => ({ value: undefined, done: true as const })),
  throw: vi.fn(async (error: Error) => {
    throw error;
  }),
  [Symbol.asyncIterator]() {
    return this;
  },
});

// Let pending promises settle, so Node has a chance to report an unhandled rejection.
const flushPromises = () => new Promise((resolve) => {
  setTimeout(resolve, 0);
});

describe('subscribeToInstanceEvents edit context functions', () => {
  const unhandledRejections: unknown[] = [];
  const onUnhandledRejection = (reason: unknown) => {
    unhandledRejections.push(reason);
  };

  beforeEach(() => {
    vi.clearAllMocks();
    unhandledRejections.length = 0;
    process.on('unhandledRejection', onUnhandledRejection);
    vi.mocked(pubSubAsyncIterator).mockImplementation(() => buildSourceIterator() as any);
    vi.mocked(internalLoadById).mockResolvedValue({ id: INSTANCE_ID } as any);
  });

  afterEach(() => {
    process.off('unhandledRejection', onUnhandledRejection);
  });

  it('should fail the subscription when the pre function rejects', async () => {
    const preError = new Error('Instance cannot be found.');
    const preFn = vi.fn(() => Promise.reject(preError));

    await expect(subscribeToInstanceEvents(undefined, context, INSTANCE_ID, [TOPIC], { preFn })).rejects.toBe(preError);
    await flushPromises();

    expect(preFn).toHaveBeenCalledTimes(1);
    expect(internalLoadById).not.toHaveBeenCalled();
    expect(pubSubAsyncIterator).not.toHaveBeenCalled();
    expect(unhandledRejections).toEqual([]);
  });

  it('should wait for the pre function before loading the instance', async () => {
    const calls: string[] = [];
    const preFn = vi.fn(async () => {
      await flushPromises();
      calls.push('pre');
    });
    vi.mocked(internalLoadById).mockImplementation(async () => {
      calls.push('load');
      return { id: INSTANCE_ID } as any;
    });

    await subscribeToInstanceEvents(undefined, context, INSTANCE_ID, [TOPIC], { preFn });

    expect(calls).toEqual(['pre', 'load']);
  });

  it('should log a warning and close the subscription when the clean function rejects', async () => {
    const cleanError = new Error('Instance cannot be found.');
    const cleanFn = vi.fn(() => Promise.reject(cleanError));

    const subscription = await subscribeToInstanceEvents(undefined, context, INSTANCE_ID, [TOPIC], { cleanFn });
    const iterator = subscription[Symbol.asyncIterator]();
    await expect(iterator.return?.()).resolves.toEqual({ value: undefined, done: true });
    await flushPromises();

    expect(cleanFn).toHaveBeenCalledTimes(1);
    expect(logApp.warn).toHaveBeenCalledWith('[SUBSCRIPTION] Error cleaning edit context', { cause: cleanError, id: INSTANCE_ID });
    expect(unhandledRejections).toEqual([]);
  });

  it('should log a warning and close the subscription when the clean function throws synchronously', async () => {
    const cleanError = new Error('Clean failed');
    const cleanFn = vi.fn(() => {
      throw cleanError;
    });

    const subscription = await subscribeToInstanceEvents(undefined, context, INSTANCE_ID, [TOPIC], { cleanFn });
    const iterator = subscription[Symbol.asyncIterator]();
    await expect(iterator.return?.()).resolves.toEqual({ value: undefined, done: true });
    await flushPromises();

    expect(logApp.warn).toHaveBeenCalledWith('[SUBSCRIPTION] Error cleaning edit context', { cause: cleanError, id: INSTANCE_ID });
    expect(unhandledRejections).toEqual([]);
  });

  it('should not log anything when the clean function succeeds', async () => {
    const cleanFn = vi.fn(async () => 'cleaned');

    const subscription = await subscribeToInstanceEvents(undefined, context, INSTANCE_ID, [TOPIC], { cleanFn });
    await subscription[Symbol.asyncIterator]().return?.();
    await flushPromises();

    expect(cleanFn).toHaveBeenCalledTimes(1);
    expect(logApp.warn).not.toHaveBeenCalled();
    expect(unhandledRejections).toEqual([]);
  });
});
