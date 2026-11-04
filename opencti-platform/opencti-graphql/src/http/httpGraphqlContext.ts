import type { Request, Response } from 'express';
import { WorkNotALiveError } from '../config/errors';
import { redisGetWork } from '../database/redis';
import { isVerifiedFormSubmission } from '../modules/form/form-submission-context';
import { createAuthenticatedContext } from './httpAuthenticatedContext';
import { checkDraftInContext } from './httpServer-draft';

// Context of a /graphql call
export const createGraphqlContext = async (req: Request, res: Response) => {
  const executeContext = await createAuthenticatedContext(req, res, 'api');
  // When context is related to a work, we need to check work status
  if (executeContext.workId) {
    // The work hash is read once for both checks: the same liveness rule as isWorkAlive, then the form submission binding
    const work = await redisGetWork(executeContext.workId);
    if (work?.is_initialized !== 'true') {
      throw WorkNotALiveError();
    }
    // Import of a Form Intake submission: lets the applicant write with the form capability
    executeContext.form_submission = isVerifiedFormSubmission(executeContext, work);
  }
  await checkDraftInContext(executeContext);
  return executeContext;
};
