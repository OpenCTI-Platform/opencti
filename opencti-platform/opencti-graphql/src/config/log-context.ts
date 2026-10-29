import { AsyncLocalStorage } from 'node:async_hooks';
import type { NextFunction, Request, Response } from 'express';

interface RequestLogContext {
  user_agent?: string;
}

const requestLogStorage = new AsyncLocalStorage<RequestLogContext>();

export const requestLogContextMiddleware = (req: Request, _res: Response, next: NextFunction) => {
  const userAgent = req.header('user-agent');
  requestLogStorage.run(userAgent ? { user_agent: userAgent } : {}, next);
};

export const getRequestLogContext = (): RequestLogContext => requestLogStorage.getStore() ?? {};

// Listeners run in the context of whoever emits, not of the request that registered them
export const bindRequestLogContext = <T extends (...args: never[]) => unknown>(fn: T): T => AsyncLocalStorage.bind(fn);
