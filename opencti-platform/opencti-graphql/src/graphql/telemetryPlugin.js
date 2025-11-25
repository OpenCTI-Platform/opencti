import { head, includes } from 'ramda';
import { stripIgnoredCharacters } from 'graphql/utilities';
import { meterManager } from '../config/tracing';
import { AUTH_FAILURE, AUTH_REQUIRED, FORBIDDEN_ACCESS } from '../config/errors';
import { isEmptyField } from '../database/utils';
import { logApp } from '../config/conf';

const getRequestError = (context) => {
  const isSuccess = isEmptyField(context.errors) || context.errors.length === 0;
  if (isSuccess) {
    return undefined;
  }
  const currentError = head(context.errors);
  const callError = currentError.originalError ? currentError.originalError : currentError;
  const isAuthenticationCall = callError.name && includes(callError.name, [AUTH_REQUIRED, AUTH_FAILURE, FORBIDDEN_ACCESS]);
  if (isAuthenticationCall) {
    return undefined;
  }
  return callError;
};

// noinspection JSUnusedGlobalSymbols
export default {
  requestDidStart: /* v8 ignore next */ () => {
    const start = Date.now();
    return {
      willSendResponse: async (sendContext) => {
        const elapsed = Date.now() - start;

        const requestError = getRequestError(sendContext);
        const operationAttributes = {
          operation: sendContext.operation?.operation ?? 'query',
          name: sendContext.operationName ?? 'Unspecified',
          status: requestError ? 'ERROR' : 'SUCCESS',
          type: requestError ? sendContext.response.body.singleResult.errors.at(0)?.name ?? requestError.name : undefined,
          user_agent: sendContext.contextValue.req.header('user-agent') ?? 'Unspecified',
        };

        if (!sendContext.operationName) {
          logApp.info('[TELEMETRY] GraphQL operation is unnamed', { query: stripIgnoredCharacters(sendContext.request?.query ?? 'undefined') });
        }

        if (requestError) {
          meterManager.error(operationAttributes);
        } else {
          meterManager.request(operationAttributes);
        }
        meterManager.latency(elapsed, operationAttributes);
      },
    };
  },
};
