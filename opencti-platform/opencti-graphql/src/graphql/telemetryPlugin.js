import { head, includes } from 'ramda';
import { meterManager } from '../config/tracing';
import { AUTH_FAILURE, AUTH_REQUIRED, FORBIDDEN_ACCESS } from '../config/errors';
import { isEmptyField } from '../database/utils';

const getRequestError = (context) => {
  const isSuccess = isEmptyField(context.errors) || context.errors.length === 0;
  if (isSuccess) {
    return undefined;
  }
  const currentError = head(context.errors);
  const callError = currentError.originalError ? currentError.originalError : currentError;
  const isAuthenticationCall = includes(callError.name, [AUTH_REQUIRED, AUTH_FAILURE, FORBIDDEN_ACCESS]);
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
        if (requestError) {
          const operation = sendContext.request.query.startsWith('mutation') ? 'mutation' : 'query';
          const operationName = sendContext.request.operationName ?? 'Unspecified';
          const type = sendContext.response.body.singleResult.errors.at(0)?.name ?? requestError.name;
          operationAttributes = { operation, name: operationName, type };
          meterManager.error(operationAttributes);
        } else {
          const operation = sendContext.operation?.operation ?? 'query';
          const operationName = sendContext.operationName ?? 'Unspecified';
          operationAttributes = { operation, name: operationName };
          meterManager.request(operationAttributes);
        }
        const stop = Date.now();
        const elapsed = stop - start;
        meterManager.latency(elapsed, operationAttributes);
      },
    };
  },
};
