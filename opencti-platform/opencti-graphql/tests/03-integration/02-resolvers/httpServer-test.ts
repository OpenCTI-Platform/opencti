import { describe, expect, it } from 'vitest';
import { extractWsSessionContext } from '../../../src/http/httpServer';
import { ADMIN_USER } from '../../utils/testQuery';

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
  });
});
