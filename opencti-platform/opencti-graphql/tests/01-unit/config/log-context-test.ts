import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { setTimeout as wait } from 'node:timers/promises';
import type { Server } from 'node:http';
import type { NextFunction, Request, Response } from 'express';
import { requestLogContextMiddleware, withRequestLogContext } from '../../../src/config/log-context';

let server: Server;
let origin: string;

beforeAll(async () => {
  const express = (await import('express')).default;
  const app = express();
  app.use(requestLogContextMiddleware);
  app.use(async (_req: Request, _res: Response, next: NextFunction) => {
    await wait(5);
    next();
  });
  app.get('/meta', async (_req, res) => {
    await wait(5);
    res.json(withRequestLogContext({ operation: 'test' }));
  });
  app.get('/override', (_req, res) => {
    res.json(withRequestLogContext({ user_agent: 'explicit' }));
  });
  app.get('/error', async () => {
    await wait(5);
    throw new Error('boom');
  });
  app.use((_err: Error, _req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json(withRequestLogContext({}));
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
  return response.json();
};

describe('request log context', () => {
  it('should add the request user agent through the middleware chain', async () => {
    const meta = await get('/meta', { 'user-agent': 'pycti/6.9.0 (my-connector)' });
    expect(meta).toEqual({ user_agent: 'pycti/6.9.0 (my-connector)', operation: 'test' });
  });

  it('should keep each concurrent request on its own user agent', async () => {
    const agents = ['agent-a', 'agent-b', 'agent-c'];
    const metas = await Promise.all(agents.map((agent) => get('/meta', { 'user-agent': agent })));
    expect(metas.map((meta) => meta.user_agent)).toEqual(agents);
  });

  it('should reach the express error handler', async () => {
    const meta = await get('/error', { 'user-agent': 'curl/8.5.0' });
    expect(meta).toEqual({ user_agent: 'curl/8.5.0' });
  });

  it('should let explicit metadata win over the request one', async () => {
    const meta = await get('/override', { 'user-agent': 'from-request' });
    expect(meta).toEqual({ user_agent: 'explicit' });
  });

  it('should add nothing when the request sends no user agent', async () => {
    // fetch always sends one, so the middleware is called directly
    let meta: Record<string, unknown> = {};
    requestLogContextMiddleware({ header: () => undefined } as unknown as Request, {} as Response, () => {
      meta = withRequestLogContext({ operation: 'test' });
    });
    expect(meta).toEqual({ operation: 'test' });
  });

  it('should add nothing outside of a request', () => {
    expect(withRequestLogContext({ operation: 'test' })).toEqual({ operation: 'test' });
  });
});
