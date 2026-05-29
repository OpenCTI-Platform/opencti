import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { callAgent, callAgentStream } from './agentApi';

const buildJsonResponse = (status: number, body: unknown, ok = status >= 200 && status < 300): Response => {
  const json = JSON.stringify(body);
  let statusText = 'OK';
  if (status === 400) statusText = 'Bad Request';
  if (status === 503) statusText = 'Service Unavailable';
  const response = {
    ok,
    status,
    statusText,
    json: async () => JSON.parse(json),
    clone() {
      return buildJsonResponse(status, body, ok);
    },
    body: null,
  };
  return response as unknown as Response;
};

const buildPlainResponse = (status: number, text: string, ok = status >= 200 && status < 300): Response => {
  const response = {
    ok,
    status,
    statusText: 'Bad Request',
    json: async () => {
      throw new SyntaxError('Unexpected token in JSON');
    },
    clone() {
      return buildPlainResponse(status, text, ok);
    },
    body: null,
  };
  return response as unknown as Response;
};

const buildSseStreamResponse = (chunks: string[]): Response => {
  let i = 0;
  const reader = {
    read: vi.fn(async () => {
      if (i >= chunks.length) {
        return { done: true, value: undefined as unknown as Uint8Array };
      }
      const chunk = new TextEncoder().encode(chunks[i]);
      i += 1;
      return { done: false, value: chunk };
    }),
    releaseLock: vi.fn(),
  };
  const response = {
    ok: true,
    status: 200,
    statusText: 'OK',
    body: { getReader: () => reader },
    json: async () => ({}),
    clone() {
      return response as unknown as Response;
    },
  };
  return response as unknown as Response;
};

describe('agentApi', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch').mockReset();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('callAgent', () => {
    it('surfaces the backend `{ error }` JSON message on non-OK responses', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        buildJsonResponse(400, { error: 'Could not find draft workspace' }),
      );

      const result = await callAgent('test-agent', 'hello');

      expect(result.status).toBe('error');
      expect(result.error).toBe('Could not find draft workspace');
      expect(result.code).toBe(400);
      expect(result.content).toBe('');
    });

    it('falls back to statusText when the error body is not JSON', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        buildPlainResponse(400, 'plain text error'),
      );

      const result = await callAgent('test-agent', 'hello');

      expect(result.status).toBe('error');
      expect(result.error).toBe('Agent call failed: Bad Request');
      expect(result.code).toBe(400);
    });

    it('returns the parsed body content on success', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        buildJsonResponse(200, { content: 'hello world', status: 'success' }),
      );

      const result = await callAgent('test-agent', 'hello');

      expect(result.status).toBe('success');
      expect(result.content).toBe('hello world');
    });
  });

  describe('callAgentStream', () => {
    it('surfaces the backend `{ error }` JSON message on non-OK responses', async () => {
      // Regression guard for the new draft-validation 400 path: without
      // `readAgentErrorBody`, the UI would see a generic "Bad Request"
      // built from `response.statusText` instead of the actionable
      // backend message.
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        buildJsonResponse(400, { error: 'Could not find draft workspace' }),
      );

      const onChunk = vi.fn();
      const result = await callAgentStream('test-agent', 'hello', onChunk);

      expect(result.status).toBe('error');
      expect(result.error).toBe('Could not find draft workspace');
      expect(result.code).toBe(400);
      expect(onChunk).not.toHaveBeenCalled();
    });

    it('falls back to statusText when the error body is not JSON', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        buildPlainResponse(400, 'plain text error'),
      );

      const result = await callAgentStream('test-agent', 'hello', vi.fn());

      expect(result.status).toBe('error');
      expect(result.error).toBe('Agent call failed: Bad Request');
    });

    it('parses streamed `stream` and `done` SSE events and surfaces backend timestamps on cache hits', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        buildSseStreamResponse([
          'data: {"type":"stream","content":"Hel"}\n\n',
          'data: {"type":"stream","content":"Hello"}\n\n',
          'data: {"type":"done","content":"Hello world","cached":true,"generated_at":"2026-05-28T10:00:00.000Z"}\n\n',
        ]),
      );

      const chunks: string[] = [];
      const result = await callAgentStream('test-agent', 'hello', (partial) => chunks.push(partial));

      expect(result.status).toBe('success');
      expect(result.content).toBe('Hello world');
      expect(result.fromCache).toBe(true);
      expect(result.generatedAt).toBe('2026-05-28T10:00:00.000Z');
      expect(chunks.at(-1)).toBe('Hello world');
    });

    it('forwards `force_refresh: true` to the backend when the caller opts to bypass the cache', async () => {
      const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        buildSseStreamResponse([
          'data: {"type":"done","content":"fresh"}\n\n',
        ]),
      );

      await callAgentStream('test-agent', 'hello', vi.fn(), undefined, true);

      const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(init.body as string);
      expect(body.force_refresh).toBe(true);
    });
  });
});
