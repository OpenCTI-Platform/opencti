import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { type ObservableResult, ValueType } from '@opentelemetry/api-metrics';
import type { Counter } from '@opentelemetry/api-metrics/build/src/types/Metric';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nodeMetrics from 'opentelemetry-node-metrics';
import type { AuthContext, AuthUser } from '../types/user';
import { ENABLED_TRACING } from './conf';

class MeterManager {
  meterProvider: MeterProvider;

  private requests: Counter | null = null;

  private errors: Counter | null = null;

  private latencies = 0;

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  request() {
    this.requests?.add(1);
  }

  error() {
    this.errors?.add(1);
  }

  latency(val: number) {
    this.latencies = val;
  }

  registerMetrics() {
    const meter = this.meterProvider.getMeter('opencti-api');
    // Register manual metrics
    // - Basic counters
    this.requests = meter.createCounter('opencti_api_requests', {
      valueType: ValueType.INT,
      description: 'Counts total number of requests'
    });
    this.errors = meter.createCounter('opencti_api_errors', {
      valueType: ValueType.INT,
      description: 'Counts total number of errors'
    });
    // - Gauges
    const latencyGauge = meter.createObservableGauge('opencti_api_latency');
    latencyGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.latencies);
    });
    // - Library metrics
    nodeMetrics(this.meterProvider, { prefix: '' });
  }
}
export const meterProvider = new MeterProvider({});
export const meterManager = new MeterManager(meterProvider);

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
