import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { setTimeout as wait } from 'node:timers/promises';
import type { Server } from 'node:http';
import type { NextFunction, Request, Response } from 'express';
import { bindRequestLogContext, getRequestLogContext, requestLogContextMiddleware } from '../../../src/config/log-context';

let server: Server;
let origin: string;
let onStreamClosed: (contexts: { bound: unknown; unbound: unknown }) => void = () => {};

beforeAll(async () => {
  const express = (await import('express')).default;
  const app = express();
  app.use(requestLogContextMiddleware);
  app.use(async (_req: Request, _res: Response, next: NextFunction) => {
    await wait(5);
    next();
  });
  app.get('/context', async (_req, res) => {
    await wait(5);
    res.json(getRequestLogContext());
  });
  app.get('/stream', async (_req, res) => {
    await wait(5);
    const contexts: { bound: unknown; unbound: unknown } = { bound: undefined, unbound: undefined };
    res.on('close', () => {
      contexts.unbound = getRequestLogContext();
    });
    res.on('close', bindRequestLogContext(() => {
      contexts.bound = getRequestLogContext();
      onStreamClosed(contexts);
    }));
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.write('data: connected\n\n');
  });
  app.get('/error', async () => {
    await wait(5);
    throw new Error('boom');
  });
  app.use((_err: Error, _req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json(getRequestLogContext());
  });

  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  origin = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

const get = async (path: string, headers: Record<string, string> = {}) => {
  const response = await fetch(`${origin}${path}`, { headers });
  return await response.json() as Record<string, unknown>;
};

describe('request log context', () => {
  it('should keep the request user agent through the middleware chain', async () => {
    const context = await get('/context', { 'user-agent': 'pycti/6.9.0 (my-connector)' });
    expect(context).toEqual({ user_agent: 'pycti/6.9.0 (my-connector)' });
  });

  it('should keep each concurrent request on its own user agent', async () => {
    const agents = ['agent-a', 'agent-b', 'agent-c'];
    const contexts = await Promise.all(agents.map((agent) => get('/context', { 'user-agent': agent })));
    expect(contexts.map((context) => context.user_agent)).toEqual(agents);
  });

  it('should reach the express error handler', async () => {
    const context = await get('/error', { 'user-agent': 'curl/8.5.0' });
    expect(context).toEqual({ user_agent: 'curl/8.5.0' });
  });

  it('should keep the request user agent in a bound listener when the client disconnects', async () => {
    const closed = new Promise<{ bound: unknown; unbound: unknown }>((resolve) => {
      onStreamClosed = resolve;
    });
    const controller = new AbortController();
    const response = await fetch(`${origin}/stream`, { headers: { 'user-agent': 'stream-client/1.0' }, signal: controller.signal });
    await response.body?.getReader().read();
    controller.abort();
    const contexts = await closed;
    expect(contexts.bound).toEqual({ user_agent: 'stream-client/1.0' });
    // Without the binding, the listener runs in the socket context
    expect(contexts.unbound).toEqual({});
  });

  it('should be empty when the request sends no user agent', () => {
    // fetch always sends one, so the middleware is called directly
    let context = {};
    requestLogContextMiddleware({ header: () => undefined } as unknown as Request, {} as Response, () => {
      context = getRequestLogContext();
    });
    expect(context).toEqual({});
  });

  it('should be empty outside of a request', () => {
    expect(getRequestLogContext()).toEqual({});
  });
});
