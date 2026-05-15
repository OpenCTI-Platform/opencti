import { head, includes } from 'ramda';
import { ATTR_DB_OPERATION_NAME } from '@opentelemetry/semantic-conventions';
import { ATTR_ENDUSER_ID, ATTR_MESSAGING_MESSAGE_BODY_SIZE } from '../telemetry/semantic-conventions';
import { AUTH_FAILURE, AUTH_REQUIRED, FORBIDDEN_ACCESS } from '../config/errors';
import { isEmptyField } from '../database/utils';

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
    let tracingSpan;
    return {
      didResolveOperation: (resolveContext) => {
        const isWrite = resolveContext.operation && resolveContext.operation.operation === 'mutation';
        const operationType = `${isWrite ? 'INSERT' : 'SELECT'}`;
        const { contextValue: context } = resolveContext;
        const endUserId = context.user?.origin?.user_id ?? 'anonymous';
        tracingSpan = context.tracing.getTracer().startSpan(`${operationType} ${resolveContext.operationName}`, {
          attributes: {
            'enduser.type': context.source,
            [ATTR_DB_OPERATION_NAME]: operationType,
            [ATTR_ENDUSER_ID]: endUserId,
          },
          kind: 1,
        });
        context.tracing.setCurrentCtx(tracingSpan);
      },
      willSendResponse: async (sendContext) => {
        if (tracingSpan) { // Tracing span can be null for invalid operations
          const requestError = getRequestError(sendContext);
          const payloadSize = Buffer.byteLength(JSON.stringify(sendContext.request.variables || {}));
          tracingSpan.setAttribute(ATTR_MESSAGING_MESSAGE_BODY_SIZE, payloadSize);
          if (requestError) {
            tracingSpan.setStatus({ code: 2, message: requestError.name });
          } else {
            tracingSpan.setStatus({ code: 1 });
          }
          tracingSpan.end();
        }
      },
    };
  },
};
