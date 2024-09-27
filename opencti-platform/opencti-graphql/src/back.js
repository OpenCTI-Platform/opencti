import 'source-map-support/register';
import blocked from 'blocked-at';
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
import { platformStart } from './boot';
import { ENABLED_EVENT_LOOP_MONITORING, ENABLED_TRACING, logApp } from './config/conf';
import { isNotEmptyField } from './database/utils';
import { TELEMETRY_SERVICE_NAME } from './utils/telemetry-attributes';

// -- Apply telemetry
// ------- Tracing
if (ENABLED_TRACING) {
  const provider = new NodeTracerProvider({
    resource: Resource.default().merge(new Resource({
      [TELEMETRY_SERVICE_NAME]: 'opencti-platform',
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
// ------- Event loop monitoring
if (ENABLED_EVENT_LOOP_MONITORING) {
  const threshold = nconf.get('app:event_loop_logs:max_time') ?? 1000; // No more than 1 sec by default
  blocked((time, stack) => {
    // For now, we only check for blocking outside graphql executeFields resolvers
    // TODO Remove after official release of graphQL 17 and resolvers adaptations
    const stackValue = stack.join();
    if (stackValue.indexOf('executeFields') === -1) {
      logApp.warn('Event loop blocking warning', { time, trace: stackValue });
    }
  }, { threshold });
}
// -- Start the platform
// noinspection JSIgnoredPromiseFromCall
platformStart();
