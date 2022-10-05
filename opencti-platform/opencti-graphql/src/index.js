import 'source-map-support/register';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { Resource } from '@opentelemetry/resources';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import nconf from 'nconf';
import { ZipkinExporter } from '@opentelemetry/exporter-zipkin';
import { boot } from './boot';
import { ENABLED_TRACING } from './config/conf';
import { isNotEmptyField } from './database/utils';

if (ENABLED_TRACING) {
  const provider = new NodeTracerProvider({
    resource: Resource.default().merge(new Resource({
      'service.name': 'opencti',
    })),
  });
  const otlpUri = nconf.get('app:telemetry:tracing:exporter_otlp');
  if (isNotEmptyField(otlpUri)) {
    const otlpExporter = new OTLPTraceExporter({ url: otlpUri, headers: {} });
    provider.addSpanProcessor(new BatchSpanProcessor(otlpExporter));
  }
  const zipKinUri = nconf.get('app:telemetry:tracing:exporter_zipkin');
  if (isNotEmptyField(otlpUri)) {
    const zipkinExporter = new ZipkinExporter({ url: zipKinUri, headers: {} });
    provider.addSpanProcessor(new BatchSpanProcessor(zipkinExporter));
  }
  provider.register();
}

// noinspection JSIgnoredPromiseFromCall
boot();
