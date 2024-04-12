import { SEMATTRS_ENDUSER_ID } from '@opentelemetry/semantic-conventions';
import { MeterProvider, MetricReader, PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { type ObservableResult, ValueType } from '@opentelemetry/api-metrics';
import type { Counter } from '@opentelemetry/api-metrics/build/src/types/Metric';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nodeMetrics from 'opentelemetry-node-metrics';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import nconf from 'nconf';
import { PrometheusExporter } from '@opentelemetry/exporter-prometheus';
import type { AuthContext, AuthUser } from '../types/user';
import { ENABLED_METRICS, ENABLED_TRACING } from './conf';
import { isNotEmptyField } from '../database/utils';

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

// ------- Metrics
const metricReaders: MetricReader[] = [];
if (ENABLED_METRICS) {
  // OTLP - JAEGER ...
  const exporterOtlp = nconf.get('app:telemetry:metrics:exporter_otlp');
  if (isNotEmptyField(exporterOtlp)) {
    const metricExporter = new OTLPMetricExporter({ url: exporterOtlp, headers: {}, concurrencyLimit: 1 });
    const metricReader = new PeriodicExportingMetricReader({ exporter: metricExporter, exportIntervalMillis: 1000 });
    metricReaders.push(metricReader);
  }
  // PROMETHEUS
  const exporterPrometheus = nconf.get('app:telemetry:metrics:exporter_prometheus');
  if (isNotEmptyField(exporterPrometheus)) {
    const prometheusExporter = new PrometheusExporter({ port: exporterPrometheus });
    metricReaders.push(prometheusExporter);
  }
}
const meterProvider = new MeterProvider({
  readers: metricReaders,
});
export const meterManager = new MeterManager(meterProvider);
// Register metrics
meterManager.registerMetrics();

export const telemetry = (context: AuthContext, user: AuthUser, spanName: string, attrs: object, fn: any) => {
  // if tracing disabled or context is not correctly configured.
  if (!ENABLED_TRACING || !context) {
    return fn();
  }
  // if tracing enabled
  const tracer = context.tracing.getTracer();
  const ctx = context.tracing.getCtx();
  const tracingSpan = tracer.startSpan(spanName, {
    attributes: {
      'enduser.type': context.source,
      [SEMATTRS_ENDUSER_ID]: user.id,
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
