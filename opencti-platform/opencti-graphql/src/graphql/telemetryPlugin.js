import { head, includes } from 'ramda';
import { SEMATTRS_DB_OPERATION, SEMATTRS_ENDUSER_ID, SEMATTRS_MESSAGING_MESSAGE_PAYLOAD_COMPRESSED_SIZE_BYTES } from '@opentelemetry/semantic-conventions';
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
    let tracingSpan;
    const start = Date.now();
    meterManager.request();
    return {
      didResolveOperation: (resolveContext) => {
        const isWrite = resolveContext.operation && resolveContext.operation.operation === 'mutation';
        const operationType = `${isWrite ? 'INSERT' : 'SELECT'}`;
        const { contextValue: context } = resolveContext;
        const endUserId = context.user?.origin?.user_id ?? 'anonymous';
        tracingSpan = context.tracing.getTracer().startSpan(`${operationType} ${resolveContext.operationName}`, {
          attributes: {
            'enduser.type': context.source,
            [SEMATTRS_DB_OPERATION]: operationType,
            [SEMATTRS_ENDUSER_ID]: endUserId,
          },
          kind: 1,
        });
        context.tracing.setCurrentCtx(tracingSpan);
      },
      willSendResponse: async (sendContext) => {
        const requestError = getRequestError(sendContext);
        const payloadSize = Buffer.byteLength(JSON.stringify(sendContext.request.variables || {}));
        // Tracing span can be null for invalid operations
        if (tracingSpan) {
          tracingSpan.setAttribute(SEMATTRS_MESSAGING_MESSAGE_PAYLOAD_COMPRESSED_SIZE_BYTES, payloadSize);
        }
        if (requestError) {
          meterManager.error();
          if (tracingSpan) {
            tracingSpan.setStatus({ code: 2, message: requestError.name });
          }
        } else {
          const stop = Date.now();
          const elapsed = stop - start;
          meterManager.latency(elapsed);
          if (tracingSpan) {
            tracingSpan.setStatus({ code: 1 });
          }
        }
        if (tracingSpan) {
          tracingSpan.end();
        }
      },
    };
  },
};
