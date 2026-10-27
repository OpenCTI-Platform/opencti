import './config/prototype-seal';
import './instrumentation';

import { context, propagation, trace } from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import { CompositePropagator, W3CBaggagePropagator, W3CTraceContextPropagator } from '@opentelemetry/core';
import { BatchSpanProcessor, TracerProvider } from '@opentelemetry/sdk-trace';
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
      new BatchSpanProcessor({ exporter: new OTLPTraceExporter({ url: otlpUri, headers: {} }) }),
    ] : [];
    const zipkinProcessors = isZipKinExporterSetUp ? [
      new BatchSpanProcessor({ exporter: new ZipkinExporter({ url: zipKinUri, headers: {} }) }),
    ] : [];
    const provider = new TracerProvider({
      resource: defaultResource().merge(resourceFromAttributes({
        [ATTR_SERVICE_NAME]: 'opencti-platform',
      })),
      spanProcessors: [
        ...otlpProcessors,
        ...zipkinProcessors,
      ],
    });
    trace.setGlobalTracerProvider(provider);
    const contextManager = new AsyncLocalStorageContextManager();
    contextManager.enable();
    context.setGlobalContextManager(contextManager);
    propagation.setGlobalPropagator(new CompositePropagator({
      propagators: [new W3CTraceContextPropagator(), new W3CBaggagePropagator()],
    }));
  }
}

// -- Start the platform
try {
  await platformStart();
} catch (reason) {
  logApp.error('Error occurs on platformStart', { reason });
}
