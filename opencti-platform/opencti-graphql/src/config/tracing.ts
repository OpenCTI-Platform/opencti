import { MeterProvider, MetricReader, PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { ValueType } from '@opentelemetry/api-metrics';
import type { Counter } from '@opentelemetry/api-metrics/build/src/types/Metric';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nodeMetrics from 'opentelemetry-node-metrics';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import nconf from 'nconf';
import { PrometheusExporter } from '@opentelemetry/exporter-prometheus';
import type { Gauge } from '@opentelemetry/api/build/src/metrics/Metric';
import type { AuthContext, AuthUser } from '../types/user';
import { ENABLED_METRICS, ENABLED_TRACING } from './conf';
import { isNotEmptyField } from '../database/utils';
import { TELEMETRY_ENDUSER_ID } from '../utils/telemetry-attributes';

class MeterManager {
  meterProvider: MeterProvider;

  private requests: Counter | null = null;

  private errors: Counter | null = null;

  private latencyGauge: Gauge | null = null;

  private directBulkGauge: Gauge | null = null;

  private sideBulkGauge: Gauge | null = null;

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  request(attributes: any) {
    this.requests?.add(1, attributes);
  }

  error(attributes: any) {
    this.errors?.add(1, attributes);
  }

  latency(val: number, attributes: any) {
    this.latencyGauge?.record(val, attributes);
  }

  directBulk(val: number, attributes: any) {
    this.directBulkGauge?.record(val, attributes);
  }

  sideBulk(val: number, attributes: any) {
    this.sideBulkGauge?.record(val, attributes);
  }

  registerMetrics() {
    const meter = this.meterProvider.getMeter('opencti-api');
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
    this.latencyGauge = meter.createGauge('opencti_api_latency', {
      valueType: ValueType.INT,
      description: 'Latency computing per query'
    });
    this.directBulkGauge = meter.createGauge('opencti_api_direct_bulk', {
      valueType: ValueType.INT,
      description: 'Size of bulks for direct absorption'
    });
    this.sideBulkGauge = meter.createGauge('opencti_api_side_bulk', {
      valueType: ValueType.INT,
      description: 'Size of bulk for absorption impacts'
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
      [TELEMETRY_ENDUSER_ID]: user.id,
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
