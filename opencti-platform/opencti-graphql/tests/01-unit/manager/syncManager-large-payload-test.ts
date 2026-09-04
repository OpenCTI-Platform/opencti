import { describe, expect, it, vi } from 'vitest';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { buildSyncEventContent, dropAttachedFilesData, isStringTooLongError } from '../../../src/manager/syncManager';

describe('syncManager large payload safeguards', () => {
  it('detects Node string-too-long errors', () => {
    expect(isStringTooLongError({ code: 'ERR_STRING_TOO_LONG' })).toBe(true);
    expect(isStringTooLongError(new Error('Cannot create a string longer than 0x1fffffe8 characters'))).toBe(true);
    expect(isStringTooLongError(new RangeError('Invalid string length'))).toBe(true);
    expect(isStringTooLongError(new Error('another error'))).toBe(false);
    expect(isStringTooLongError(new Error('Invalid string length'))).toBe(false);
  });

  it('drops attached files data and returns dropped files details', () => {
    const syncData: Record<string, any> = {
      extensions: {
        [STIX_EXT_OCTI]: {
          files: [
            { uri: '/storage/get/a', data: 'A'.repeat(32) },
            { uri: '/storage/get/b' },
            { uri: '/storage/get/c', data: 'C'.repeat(8) },
          ],
        },
      },
    };

    const droppedFiles = dropAttachedFilesData(syncData);

    expect(droppedFiles).toEqual([
      { fileUri: '/storage/get/a', dataLength: 32 },
      { fileUri: '/storage/get/c', dataLength: 8 },
    ]);
    expect(syncData.extensions[STIX_EXT_OCTI].files[0]).not.toHaveProperty('data');
    expect(syncData.extensions[STIX_EXT_OCTI].files[1]).not.toHaveProperty('data');
    expect(syncData.extensions[STIX_EXT_OCTI].files[2]).not.toHaveProperty('data');
  });

  it('retries payload encoding after dropping attachment data on ERR_STRING_TOO_LONG', () => {
    const syncData: Record<string, any> = {
      extensions: {
        [STIX_EXT_OCTI]: {
          id: 'entity-id',
          type: 'Report',
          files: [{ uri: '/storage/get/huge', data: 'H'.repeat(64) }],
        },
      },
    };
    const logger = { error: vi.fn(), warn: vi.fn(), info: vi.fn(), query: vi.fn(), _log: vi.fn(), debug: vi.fn() };
    const encodeToBase64 = vi
      .fn()
      .mockImplementationOnce(() => {
        const error = new Error('Cannot create a string longer than 0x1fffffe8 characters');
        (error as any).code = 'ERR_STRING_TOO_LONG';
        throw error;
      })
      .mockImplementation((payload: string) => `encoded:${payload.length}`);

    const content = buildSyncEventContent({
      syncId: 'sync-id',
      lastEventId: 'event-id',
      eventType: 'create',
      syncData,
      eventContext: { user_id: 'u-1' },
      encodeToBase64,
      logger,
    });

    expect(content).toMatch(/^encoded:/);
    expect(encodeToBase64).toHaveBeenCalledTimes(2);
    const firstPayload = JSON.parse(encodeToBase64.mock.calls[0][0]);
    const secondPayload = JSON.parse(encodeToBase64.mock.calls[1][0]);
    expect(firstPayload.data.extensions[STIX_EXT_OCTI].files[0].data).toBeDefined();
    expect(secondPayload.data.extensions[STIX_EXT_OCTI].files[0].data).toBeUndefined();
    expect(logger.error).toHaveBeenCalledTimes(1);
  });

  it('retries payload encoding after dropping attachment data on JSON.stringify RangeError', () => {
    const syncData: Record<string, any> = {
      extensions: {
        [STIX_EXT_OCTI]: {
          id: 'entity-id',
          type: 'Report',
          files: [{ uri: '/storage/get/huge', data: 'H'.repeat(64) }],
        },
      },
    };
    const logger = { error: vi.fn(), warn: vi.fn(), info: vi.fn(), query: vi.fn(), _log: vi.fn(), debug: vi.fn() };
    const encodeToBase64 = vi
      .fn()
      .mockImplementationOnce(() => {
        throw new RangeError('Invalid string length');
      })
      .mockImplementation((payload: string) => `encoded:${payload.length}`);

    const content = buildSyncEventContent({
      syncId: 'sync-id',
      lastEventId: 'event-id',
      eventType: 'create',
      syncData,
      eventContext: { user_id: 'u-1' },
      encodeToBase64,
      logger,
    });

    expect(content).toMatch(/^encoded:/);
    expect(encodeToBase64).toHaveBeenCalledTimes(2);
    const secondPayload = JSON.parse(encodeToBase64.mock.calls[1][0]);
    expect(secondPayload.data.extensions[STIX_EXT_OCTI].files[0].data).toBeUndefined();
    expect(logger.error).toHaveBeenCalledTimes(1);
  });

  it('rethrows ERR_STRING_TOO_LONG when no attachment data can be dropped', () => {
    const syncData: Record<string, any> = {
      extensions: {
        [STIX_EXT_OCTI]: {
          files: [{ uri: '/storage/get/no-data' }],
        },
      },
    };
    const encodeToBase64 = vi.fn(() => {
      const error = new Error('Cannot create a string longer than 0x1fffffe8 characters');
      (error as any).code = 'ERR_STRING_TOO_LONG';
      throw error;
    });

    expect(() => buildSyncEventContent({
      syncId: 'sync-id',
      lastEventId: 'event-id',
      eventType: 'create',
      syncData,
      eventContext: {},
      encodeToBase64,
    })).toThrowError(/Cannot create a string longer than/);
    expect(encodeToBase64).toHaveBeenCalledTimes(1);
  });
});
