import type { Request, Response } from 'express';
import { WorkNotALiveError } from '../config/errors';
import { isWorkAlive } from '../domain/work';
import { isVerifiedFormSubmission } from '../modules/form/form-submission-context';
import { createAuthenticatedContext } from './httpAuthenticatedContext';
import { checkDraftInContext } from './httpServer-draft';

// Context of a /graphql call
export const createGraphqlContext = async (req: Request, res: Response) => {
  const executeContext = await createAuthenticatedContext(req, res, 'api');
  // When context is related to a work, we need to check work status
  if (executeContext.workId) {
    const workStillAlive = await isWorkAlive(executeContext, executeContext.user, executeContext.workId);
    if (!workStillAlive) {
      throw WorkNotALiveError();
    }
    // Import of a Form Intake submission: lets the applicant write with the form capability
    executeContext.form_submission = await isVerifiedFormSubmission(executeContext);
  }
  await checkDraftInContext(executeContext);
  return executeContext;
};
