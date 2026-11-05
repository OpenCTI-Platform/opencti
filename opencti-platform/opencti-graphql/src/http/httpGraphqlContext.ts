import type { Request, Response } from 'express';
import { checkIntakeContext } from '../intake/intake-context-rules';
import { createAuthenticatedContext } from './httpAuthenticatedContext';

// Context of a /graphql call
export const createGraphqlContext = async (req: Request, res: Response) => {
  const executeContext = await createAuthenticatedContext(req, res, 'api');
  // Work alive, form submission, draft open: the rules shared with the in-process intake
  await checkIntakeContext(executeContext);
  return executeContext;
};
