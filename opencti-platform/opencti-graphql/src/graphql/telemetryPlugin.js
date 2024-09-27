import { head, includes } from 'ramda';
import { meterManager } from '../config/tracing';
import { AUTH_FAILURE, AUTH_REQUIRED, FORBIDDEN_ACCESS } from '../config/errors';
import { isEmptyField } from '../database/utils';
import { TELEMETRY_DB_OPERATION, TELEMETRY_ENDUSER_ID, TELEMETRY_MESSAGING_MESSAGE_PAYLOAD_COMPRESSED_SIZE_BYTES } from '../utils/telemetry-attributes';

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
    return {
      didResolveOperation: (resolveContext) => {
        const isWrite = resolveContext.operation && resolveContext.operation.operation === 'mutation';
        const operationType = `${isWrite ? 'INSERT' : 'SELECT'}`;
        const { contextValue: context } = resolveContext;
        const endUserId = context.user?.origin?.user_id ?? 'anonymous';
        tracingSpan = context.tracing.getTracer().startSpan(`${operationType} ${resolveContext.operationName}`, {
          attributes: {
            'enduser.type': context.source,
            [TELEMETRY_DB_OPERATION]: operationType,
            [TELEMETRY_ENDUSER_ID]: endUserId,
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
          tracingSpan.setAttribute(TELEMETRY_MESSAGING_MESSAGE_PAYLOAD_COMPRESSED_SIZE_BYTES, payloadSize);
        }
        if (requestError) {
          const operation = sendContext.request.query.startsWith('mutation') ? 'mutation' : 'query';
          const { operationName } = sendContext.request;
          const type = sendContext.response.body.singleResult.errors.at(0)?.name ?? requestError.name;
          const operationAttributes = { operation, name: operationName, type };
          meterManager.error(operationAttributes);
          if (tracingSpan) {
            tracingSpan.setStatus({ code: 2, message: requestError.name });
          }
        } else {
          const operation = sendContext.operation?.operation ?? 'query';
          const operationName = sendContext.operationName ?? 'Unspecified';
          const operationAttributes = { operation, name: operationName };
          meterManager.request(operationAttributes);
          const stop = Date.now();
          const elapsed = stop - start;
          meterManager.latency(elapsed, operationAttributes);
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
