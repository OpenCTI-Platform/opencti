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
        const requestError = getRequestError(sendContext);
        let operationAttributes;
        const operationName = sendContext.operationName ?? 'Unspecified';
        const operation = sendContext.operation?.operation ?? 'query';
        if (operationName === 'Unspecified') {
          logApp.error('TELEMETRY PLUGIN UNDEFINED OPERATION', { query: stripIgnoredCharacters(sendContext.request.query) });
        }
        if (requestError) {
          const type = sendContext.response.body.singleResult.errors.at(0)?.name ?? requestError.name;
          operationAttributes = { operation, name: operationName, status: 'ERROR', type };
          meterManager.error(operationAttributes);
        } else {
          operationAttributes = { operation, name: operationName, status: 'SUCCESS' };
          meterManager.request(operationAttributes);
        }
        const stop = Date.now();
        const elapsed = stop - start;
        meterManager.latency(elapsed, operationAttributes);
      },
    };
  },
};
