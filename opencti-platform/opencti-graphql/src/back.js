import './instrumentation';

import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { defaultResource, resourceFromAttributes } from '@opentelemetry/resources';
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
import { ATTR_SERVICE_NAME } from '@opentelemetry/semantic-conventions';
import { platformStart } from './boot';
import { ENABLED_TRACING, logApp } from './config/conf';
import { isNotEmptyField } from './database/utils';

// -- Apply telemetry
// ------- Tracing
if (ENABLED_TRACING) {
  const otlpUri = nconf.get('app:telemetry:tracing:exporter_otlp');
  const isOtlpExporterSetUp = isNotEmptyField(otlpUri);
  const zipKinUri = nconf.get('app:telemetry:tracing:exporter_zipkin');
  const isZipKinExporterSetUp = isNotEmptyField(zipKinUri);
  if (isOtlpExporterSetUp || isZipKinExporterSetUp) {
    const otlpProcessors = isOtlpExporterSetUp ? [
      new BatchSpanProcessor(new OTLPTraceExporter({ url: otlpUri, headers: {} })),
    ] : [];
    const zipkinProcessors = isZipKinExporterSetUp ? [
      new BatchSpanProcessor(new ZipkinExporter({ url: zipKinUri, headers: {} })),
    ] : [];
    const provider = new NodeTracerProvider({
      resource: defaultResource().merge(resourceFromAttributes({
        [ATTR_SERVICE_NAME]: 'opencti-platform',
      })),
      spanProcessors: [
        ...otlpProcessors,
        ...zipkinProcessors,
      ],
    });
    provider.register();
  }
}

// -- Start the platform
// noinspection JSIgnoredPromiseFromCall
platformStart().catch((reason) => logApp.error('Error occurs on platformStart', { reason }));
