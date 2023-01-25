import 'source-map-support/register';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { Resource } from '@opentelemetry/resources';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import nconf from 'nconf';
import { ZipkinExporter } from '@opentelemetry/exporter-zipkin';
import { PrometheusExporter } from '@opentelemetry/exporter-prometheus';
import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { platformStart, platformStop } from './boot';
import { ENABLED_METRICS, ENABLED_TRACING } from './config/conf';
import { isNotEmptyField, wait } from './database/utils';
import { meterManager, meterProvider } from './config/tracing';

// -- Apply telemetry
// ------- Tracing
if (ENABLED_TRACING) {
  const provider = new NodeTracerProvider({
    resource: Resource.default().merge(new Resource({
      'service.name': 'opencti-platform',
    })),
  });
  // OTLP - JAEGER ...
  const otlpUri = nconf.get('app:telemetry:tracing:exporter_otlp');
  if (isNotEmptyField(otlpUri)) {
    const otlpExporter = new OTLPTraceExporter({ url: otlpUri, headers: {} });
    provider.addSpanProcessor(new BatchSpanProcessor(otlpExporter));
  }
  // ZIPKIN
  const zipKinUri = nconf.get('app:telemetry:tracing:exporter_zipkin');
  if (isNotEmptyField(otlpUri)) {
    const zipkinExporter = new ZipkinExporter({ url: zipKinUri, headers: {} });
    provider.addSpanProcessor(new BatchSpanProcessor(zipkinExporter));
  }
  // Registration
  provider.register();
}
// ------- Metrics
if (ENABLED_METRICS) {
  // OTLP - JAEGER ...
  const exporterOtlp = nconf.get('app:telemetry:metrics:exporter_otlp');
  if (isNotEmptyField(exporterOtlp)) {
    const metricExporter = new OTLPMetricExporter({ url: exporterOtlp, headers: {}, concurrencyLimit: 1 });
    meterProvider.addMetricReader(new PeriodicExportingMetricReader({ exporter: metricExporter, exportIntervalMillis: 1000 }));
  }
  // PROMETHEUS
  const exporterPrometheus = nconf.get('app:telemetry:metrics:exporter_prometheus');
  if (isNotEmptyField(exporterPrometheus)) {
    const exporter = new PrometheusExporter({ port: exporterPrometheus });
    meterProvider.addMetricReader(exporter);
  }
  // Register metrics
  meterManager.registerMetrics();
}

// -- Start the platform
// noinspection JSIgnoredPromiseFromCall
platformStart().then(() => wait(15000)).then(() => platformStop());
