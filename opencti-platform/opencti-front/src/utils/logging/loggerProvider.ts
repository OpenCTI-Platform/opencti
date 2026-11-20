import { createNoopMeter, logs } from '@opentelemetry/api';
import type { Attributes, MeterProvider } from '@opentelemetry/api';
import { BatchLogRecordProcessor, ConsoleLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from '@opentelemetry/sdk-logs';
import type { LogRecordProcessor } from '@opentelemetry/sdk-logs';
import { DedupLogRecordProcessor, RECORDS_SUPPRESSED_EVENT_NAME } from './DedupLogRecordProcessor';
import type { SuppressedRecords } from './DedupLogRecordProcessor';
import { reloadOnceForChunkError, warnIfEnvironmentFailure } from './environmentFailures';
import { GraphQLLogRecordExporter } from './GraphQLLogRecordExporter';
import { SEVERITY_NUMBERS, logger } from './logger';

let provider: LoggerProvider | undefined;
let dropReported = false;

const reportSuppressed = (suppressed: SuppressedRecords) => {
  logger.info('Duplicate log records suppressed', {
    eventName: RECORDS_SUPPRESSED_EVENT_NAME,
    data: { suppressed: { count: suppressed.count, event_name: suppressed.eventName, level: suppressed.level } },
  });
};

const dropAwareMeterProvider: MeterProvider = {
  getMeter: () => Object.assign(createNoopMeter(), {
    createCounter: () => ({
      add: (_count: number, attributes?: Attributes) => {
        if (dropReported || attributes?.['error.type'] !== 'queue_full') {
          return;
        }
        dropReported = true;
        setTimeout(() => {
          logger.info('Log records dropped, queue full', { eventName: 'opencti.frontend.records_dropped' });
        }, 5_000);
      },
    }),
  }),
};

// ERROR records are flushed right away, as the old frontendErrorLog did,
// so a crash is not lost if the user reloads within the batch delay.
export const flushOnError = (delegate: LogRecordProcessor): LogRecordProcessor => ({
  onEmit: (record, context) => {
    delegate.onEmit(record, context);
    if ((record.severityNumber ?? 0) >= SEVERITY_NUMBERS.ERROR) {
      delegate.forceFlush().catch(() => {});
    }
  },
  forceFlush: (options) => delegate.forceFlush(options),
  shutdown: () => delegate.shutdown(),
});

const buildShippingProcessor = (isDev: boolean) => {
  if (isDev) {
    return new SimpleLogRecordProcessor({ exporter: new ConsoleLogRecordExporter() });
  }
  // The browser build of this processor also flushes when the document is hidden
  return flushOnError(new BatchLogRecordProcessor({
    exporter: new GraphQLLogRecordExporter(),
    scheduledDelayMillis: 5_000,
    maxExportBatchSize: 50,
    maxQueueSize: 500,
    selfObsMeterProvider: dropAwareMeterProvider,
  }));
};

export const onUncaughtError = (event: ErrorEvent) => {
  const error = event.error ?? event.message;
  if (warnIfEnvironmentFailure(error, { source: 'uncaught_error' })) {
    return;
  }
  logger.error('Uncaught error', {
    eventName: 'opencti.frontend.uncaught_error',
    error,
  });
};

export const onUnhandledRejection = (event: PromiseRejectionEvent) => {
  if (warnIfEnvironmentFailure(event.reason, { source: 'unhandled_rejection' })) {
    return;
  }
  logger.error('Unhandled promise rejection', {
    eventName: 'opencti.frontend.unhandled_rejection',
    error: event.reason,
  });
};

// Vite dispatches this when a lazy chunk or its CSS fails to load, typically in a tab opened before
// an upgrade that removed the hashed file. The event is deliberately not cancelled: preventDefault()
// would resolve the import to undefined, and lazy() would crash with an unclassified error before
// the reload completes. Left alone, the original error reaches the error boundary or the listeners
// above, which log it at warn.
const onPreloadError = (event: VitePreloadErrorEvent) => {
  reloadOnceForChunkError(event.payload);
};

// The batch processor flushes itself when the page is hidden, but not the dedup layer
// above it, so pending suppressed counts would otherwise never be reported.
const onPageHidden = () => {
  if (document.visibilityState === 'hidden') {
    provider?.forceFlush().catch(() => {});
  }
};

// Until this runs, logger calls are no-ops, so importing logger anywhere is safe.
export const initLogger = (isDev: boolean = import.meta.env.DEV): LoggerProvider => {
  if (provider) {
    return provider;
  }
  provider = new LoggerProvider({
    processors: [new DedupLogRecordProcessor(buildShippingProcessor(isDev), { onSuppressed: reportSuppressed })],
    loggerConfigurator: () => ({
      enabled: true,
      minimumSeverity: isDev ? SEVERITY_NUMBERS.DEBUG : SEVERITY_NUMBERS.INFO,
      traceBased: false,
    }),
  });
  logs.setGlobalLoggerProvider(provider);
  window.addEventListener('error', onUncaughtError);
  window.addEventListener('unhandledrejection', onUnhandledRejection);
  window.addEventListener('vite:preloadError', onPreloadError);
  document.addEventListener('visibilitychange', onPageHidden);
  return provider;
};
