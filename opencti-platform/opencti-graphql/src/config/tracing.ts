import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import type { AuthContext, AuthUser } from '../types/user';
import { ENABLED_TRACING } from './conf';

export const telemetry = (context: AuthContext, user: AuthUser, spanName: string, attrs: object, fn: any) => {
  // if tracing disabled
  if (!ENABLED_TRACING) {
    return fn();
  }
  // if tracing enabled
  const tracer = context.tracing.getTracer();
  const ctx = context.tracing.getCtx();
  const tracingSpan = tracer.startSpan(spanName, {
    attributes: {
      'enduser.type': context.source,
      [SemanticAttributes.ENDUSER_ID]: user.id,
      ...attrs
    },
    kind: 2 }, ctx);
  return fn().then((data: any) => {
    tracingSpan.setStatus({ code: 1 });
    tracingSpan.end();
    return data;
  }).catch((err: Error) => {
    tracingSpan.setStatus({ code: 2 });
    tracingSpan.end();
    throw err;
  });
};
