import './instrumentation';

import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { Resource } from '@opentelemetry/resources';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import nconf from 'nconf';
import { ZipkinExporter } from '@opentelemetry/exporter-zipkin';
// region static graphql modules, need to be imported before everything
import './modules/index';
// import managers
import './manager/index';
// import tracing
import './config/tracing';
// endregion
import { SEMRESATTRS_SERVICE_NAME } from '@opentelemetry/semantic-conventions';
import { platformStart } from './boot';
import { ENABLED_TRACING, logApp } from './config/conf';
import { isNotEmptyField } from './database/utils';

// -- Apply telemetry
// ------- Tracing
if (ENABLED_TRACING) {
  const provider = new NodeTracerProvider({
    resource: Resource.default().merge(new Resource({
      [SEMRESATTRS_SERVICE_NAME]: 'opencti-platform',
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

// -- Start the platform
// noinspection JSIgnoredPromiseFromCall
platformStart().catch((reason) => logApp.error('Error occurs on platformStart', { reason }));
