import { describe, expect, it, vi } from 'vitest';
import { ADMIN_USER } from '../../../utils/testQuery';
import { extractWsSessionContext } from '../../../../src/http/httpServer';

describe('httpServer', () => {
  describe('extractWsSessionContext', async () => {
    const context = {
      extra: {
        request: {
          session: {
            user: {
              id: ADMIN_USER.id,
            },
          },
        },
        socket: {
          _socket: {
            remoteAddress: '::1',
          },
        } },
    };

    const brokenContext = {
      extra: {
        request: {
          session: {
            user: '',
          },
        },
        socket: {
          _socket: '',
        },
      },
    };

    it('should initialize context.user correctly and context.batch with required loaders for websocket subscriptions with correct context', async () => {
      const sessionContext = await extractWsSessionContext(context);

      // User is defined
      expect(sessionContext?.user).toBeDefined();
      expect(sessionContext?.user?.id).toEqual(ADMIN_USER.id);
      // Batch is defined
      expect(sessionContext?.batch).toBeDefined();
      expect(sessionContext?.batch?.fileMarkingsBatchLoader.load).toBeTypeOf('function');
      expect(sessionContext?.batch?.markingsBatchLoader.load).toBeTypeOf('function');
    });

    it('should throw an error with broken context', async () => {
      await expect(extractWsSessionContext(brokenContext)).rejects.toThrow('User must be authenticated');
    });

    it('should refuse a session whose user does not exist, and replace the session', async () => {
      const regenerate = vi.fn((callback: (err?: unknown) => void) => callback());
      const unknownUserContext = {
        extra: {
          request: { session: { user: { id: '5f0c4a3e-1b7d-4c2e-9a8f-6d3b2e1c0a99' }, regenerate } },
          socket: { _socket: { remoteAddress: '::1' } },
        },
      };
      await expect(extractWsSessionContext(unknownUserContext)).rejects.toThrow('User must be authenticated');
      expect(regenerate).toHaveBeenCalledTimes(1);
    });
  });
});
