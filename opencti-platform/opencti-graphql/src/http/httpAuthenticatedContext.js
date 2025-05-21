import { executionContext, isUserInPlatformOrganization, SYSTEM_USER } from '../utils/access';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { authenticateUserFromRequest, userWithOrigin } from '../domain/user';
import { isNotEmptyField } from '../database/utils';
import { logApp } from '../config/conf';

export const createAuthenticatedContext = async (req, res, contextName) => {
  const executeContext = executionContext(contextName);
  executeContext.req = req;
  executeContext.res = res;
  const settings = await getEntityFromCache(executeContext, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  executeContext.otp_mandatory = settings.otp_mandatory ?? false;
  executeContext.workId = req.headers['opencti-work-id']; // Api call comes from a worker processing
  executeContext.draft_context = req.headers['opencti-draft-id']; // Api call is to be made is specific draft context
  executeContext.eventId = req.headers['opencti-event-id']; // Api call is due to listening event
  executeContext.previousStandard = req.headers['previous-standard']; // Previous standard id
  executeContext.synchronizedUpsert = req.headers['synchronized-upsert'] === 'true'; // If full sync needs to be done
  try {
    const user = await authenticateUserFromRequest(executeContext, req);
    if (user) {
      if (!Object.keys(req.headers).some((k) => k === 'opencti-draft-id')) {
        executeContext.draft_context = user.draft_context;
      }
      executeContext.user = userWithOrigin(req, user);
      executeContext.user_otp_validated = true;
      executeContext.user_with_session = isNotEmptyField(req.session?.user);
      if (executeContext.user_with_session) {
        executeContext.user_otp_validated = req.session?.user.otp_validated ?? false;
      }
      executeContext.user_inside_platform_organization = isUserInPlatformOrganization(user, settings);
    }
  } catch (error) {
    logApp.error('Fail to authenticate the user in graphql context hook', { cause: error });
  }
  return executeContext;
};
