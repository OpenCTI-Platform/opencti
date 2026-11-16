import type { ApolloServerPlugin, BaseContext, GraphQLRequestContextWillSendResponse } from '@apollo/server';
import { logApp } from '../config/conf';
import { getEntitiesMapFromCache } from '../database/cache';
import { reportExpectation } from '../domain/work';
import { userWithOrigin } from '../modules/user/user-domain';
import { ENTITY_TYPE_USER } from '../modules/user/user-types';
import type { AuthContext, AuthUser } from '../types/user';
import { isUserHasCapability, SYSTEM_USER } from '../utils/access';

// The worker asked for it on a successful mutation of a work
const shouldReportExpectation = (requestContext: GraphQLRequestContextWillSendResponse<BaseContext>): boolean => {
  const context = requestContext.contextValue as AuthContext;
  const isRequested = context.reportExpectationRequested === true;
  const hasWork = Boolean(context.workId);
  const isMutation = requestContext.operation?.operation === 'mutation';
  const hasErrors = (requestContext.errors?.length ?? 0) > 0;
  return isRequested && hasWork && isMutation && !hasErrors;
};

// The user of the worker's separate reportExpectation call: the credential owner, never the impersonated applicant
const resolveCredentialUser = async (context: AuthContext): Promise<AuthUser | undefined> => {
  const { user, req } = context;
  const realUserId = context.real_authentication_id;
  if (!user || !realUserId || realUserId === user.id) {
    return user;
  }
  const platformUsers = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const realUser = platformUsers.get(realUserId);
  if (!realUser || !req) {
    return undefined;
  }
  return userWithOrigin(req, realUser, { applicant_id: undefined });
};

const resolveCredentialUserOrNothing = async (context: AuthContext): Promise<AuthUser | undefined> => {
  try {
    return await resolveCredentialUser(context);
  } catch (error) {
    logApp.warn('Cannot resolve the worker user to report work expectation', { cause: error, workId: context.workId });
    return undefined;
  }
};

// Same capabilities as the workEdit mutation
const canReportWork = (user: AuthUser): boolean => {
  return isUserHasCapability(user, 'CONNECTORAPI') || isUserHasCapability(user, 'MODULES_MODMANAGE');
};

// Confirmed even on failure, the worker never retried its own reportExpectation call either
const reportAndConfirm = async (requestContext: GraphQLRequestContextWillSendResponse<BaseContext>, credentialUser: AuthUser): Promise<void> => {
  const context = requestContext.contextValue as AuthContext;
  try {
    await reportExpectation({ ...context, user: credentialUser }, credentialUser, context.workId, null);
  } catch (error) {
    logApp.warn('Cannot report work expectation from the worker call', { cause: error, workId: context.workId });
  }
  requestContext.response.http.headers.set('opencti-expectation-reported', 'true');
};

// Does the worker's per object +1 with its create call, so the worker skips its separate reportExpectation call
const workExpectationPlugin: ApolloServerPlugin = {
  requestDidStart: async () => ({
    willSendResponse: async (requestContext) => {
      if (!shouldReportExpectation(requestContext)) {
        return;
      }
      const credentialUser = await resolveCredentialUserOrNothing(requestContext.contextValue as AuthContext);
      const isAllowed = credentialUser !== undefined && canReportWork(credentialUser);
      if (!isAllowed) {
        return;
      }
      await reportAndConfirm(requestContext, credentialUser);
    },
  }),
};

export default workExpectationPlugin;
