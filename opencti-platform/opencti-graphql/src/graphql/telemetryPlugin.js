import { head } from 'ramda';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';

// noinspection JSUnusedGlobalSymbols
export default {
  requestDidStart: /* istanbul ignore next */ () => {
    let tracingSpan;
    return {
      didResolveOperation: (resolveContext) => {
        const isWrite = resolveContext.operation && resolveContext.operation.operation === 'mutation';
        const operationType = `${isWrite ? 'INSERT' : 'SELECT'}`;
        const { context } = resolveContext;
        const endUserId = context.user?.origin?.user_id ?? 'anonymous';
        tracingSpan = context.tracing.getTracer().startSpan(`${operationType} ${resolveContext.operationName}`, {
          attributes: {
            'enduser.type': context.source,
            [SemanticAttributes.DB_OPERATION]: operationType,
            [SemanticAttributes.ENDUSER_ID]: endUserId,
          },
          kind: 1,
        });
        context.tracing.setCurrentCtx(tracingSpan);
      },
      willSendResponse: async (sendContext) => {
        const isError = sendContext.errors && sendContext.errors.length > 0;
        const payloadSize = Buffer.byteLength(JSON.stringify(sendContext.request.variables || {}));
        tracingSpan.setAttribute(SemanticAttributes.MESSAGING_MESSAGE_PAYLOAD_COMPRESSED_SIZE_BYTES, payloadSize);
        if (isError) {
          const currentError = head(sendContext.errors);
          const callError = currentError.originalError ? currentError.originalError : currentError;
          tracingSpan.setStatus({ code: 2, message: callError.name });
        } else {
          tracingSpan.setStatus({ code: 1 });
        }
        tracingSpan.end();
      },
    };
  },
};
