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

// Explicit metadata wins, so a caller can still log the user agent of another request
export const withRequestLogContext = (meta: Record<string, unknown>) => {
  return { ...requestLogStorage.getStore(), ...meta };
};
