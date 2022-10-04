import 'source-map-support/register';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { Resource } from '@opentelemetry/resources';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { boot } from './boot';

const provider = new NodeTracerProvider({
  resource: Resource.default().merge(new Resource({
    'service.name': 'opencti',
  })),
});

const otlp = new OTLPTraceExporter({
  url: 'http://192.168.2.36:4318/v1/traces',
  headers: {},
});

provider.addSpanProcessor(new BatchSpanProcessor(otlp));
// provider.addSpanProcessor(new SimpleSpanProcessor(new ConsoleSpanExporter()));
provider.register();

// noinspection JSIgnoredPromiseFromCall
boot();
