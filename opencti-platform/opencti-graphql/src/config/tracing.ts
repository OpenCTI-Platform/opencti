// eslint-disable-next-line import/no-unresolved
import { ATTR_ENDUSER_ID } from '@opentelemetry/semantic-conventions/incubating';
import { MeterProvider, MetricReader, PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { ValueType } from '@opentelemetry/api-metrics';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nodeMetrics from 'opentelemetry-node-metrics';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import nconf from 'nconf';
import { PrometheusExporter } from '@opentelemetry/exporter-prometheus';
import { SpanKind } from '@opentelemetry/api';
import type { AuthContext, AuthUser } from '../types/user';
import { ENABLED_METRICS, ENABLED_TRACING } from './conf';
import { isNotEmptyField } from '../database/utils';

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

const meter = meterProvider.getMeter('opencti-api');

// - Basic counters
const sentEmails = meter.createCounter('opencti_sent_email', {
  valueType: ValueType.INT,
  description: 'Counts total number of email sent'
});
const requests = meter.createCounter('opencti_api_requests', {
  valueType: ValueType.INT,
  description: 'Counts total number of requests'
});
const errors = meter.createCounter('opencti_api_errors', {
  valueType: ValueType.INT,
  description: 'Counts total number of errors'
});
// - Histograms
const latencyHistogram = meter.createHistogram('opencti_api_latency', {
  valueType: ValueType.INT,
  description: 'Latency computing per query',
  advice: { explicitBucketBoundaries: [0, 100, 500, 2000, 5000] }
});
// - Gauges
const directBulkGauge = meter.createGauge('opencti_api_direct_bulk', {
  valueType: ValueType.INT,
  description: 'Size of bulks for direct absorption'
});
const sideBulkGauge = meter.createGauge('opencti_api_side_bulk', {
  valueType: ValueType.INT,
  description: 'Size of bulk for absorption impacts'
});
// - Library metrics
nodeMetrics(meterProvider, { prefix: '' });

export const meterManager = {
  request: (attributes: any) => {
    requests.add(1, attributes);
  },
  emailSent: (attributes: any) => {
    sentEmails.add(1, attributes);
  },
  error: (attributes: any) => {
    errors.add(1, attributes);
  },
  latency: (val: number, attributes: any) => {
    latencyHistogram.record(val, attributes);
  },
  directBulk: (val: number, attributes: any) => {
    directBulkGauge.record(val, attributes);
  },
  sideBulk: (val: number, attributes: any) => {
    sideBulkGauge.record(val, attributes);
  }
};

export const telemetry = async (context: AuthContext, user: AuthUser, spanName: string, attrs: object, fn: any) => {
  // if tracing disabled or context is not correctly configured.
  if (!ENABLED_TRACING || !context) {
    return fn();
  }
  // if tracing enabled
  const tracer = context.tracing.getTracer();
  const ctx = context.tracing.getCtx();
  const tracingSpan = tracer.startSpan(
    spanName,
    {
      attributes: {
        'enduser.type': context.source,
        [ATTR_ENDUSER_ID]: user.id,
        ...attrs
      },
      kind: SpanKind.CLIENT
    },
    ctx
  );

  try {
    const data = await fn();
    tracingSpan.setStatus({ code: 1 });
    tracingSpan.end();
    return data;
  } catch (err) {
    tracingSpan.setStatus({ code: 2 });
    tracingSpan.end();
    throw err;
  }
};
