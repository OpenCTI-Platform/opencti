import { logs } from '@opentelemetry/api-logs';
import { BatchLogRecordProcessor, ConsoleLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { DedupLogRecordProcessor, RECORDS_SUPPRESSED_EVENT_NAME } from './DedupLogRecordProcessor';
import type { SuppressedRecords } from './DedupLogRecordProcessor';
import { GraphQLLogRecordExporter } from './GraphQLLogRecordExporter';
import { SEVERITY_NUMBERS, logger } from './logger';

let provider: LoggerProvider | undefined;

const reportSuppressed = (suppressed: SuppressedRecords) => {
  logger.info('Duplicate log records suppressed', {
    eventName: RECORDS_SUPPRESSED_EVENT_NAME,
    data: { suppressed: { count: suppressed.count, event_name: suppressed.eventName, level: suppressed.level } },
  });
};

const buildShippingProcessor = (isDev: boolean) => {
  if (isDev) {
    return new SimpleLogRecordProcessor({ exporter: new ConsoleLogRecordExporter() });
  }
  // The browser build of this processor also flushes when the document is hidden
  return new BatchLogRecordProcessor({
    exporter: new GraphQLLogRecordExporter(),
    scheduledDelayMillis: 5_000,
    maxExportBatchSize: 50,
    maxQueueSize: 500,
  });
};

const onUncaughtError = (event: ErrorEvent) => {
  logger.error('Uncaught error', {
    eventName: 'opencti.frontend.uncaught_error',
    error: event.error ?? event.message,
  });
};

const onUnhandledRejection = (event: PromiseRejectionEvent) => {
  logger.error('Unhandled promise rejection', {
    eventName: 'opencti.frontend.unhandled_rejection',
    error: event.reason,
  });
};

// Until this runs, logger calls are no-ops, so importing logger anywhere is safe.
export const initLogger = (isDev: boolean = import.meta.env.DEV): LoggerProvider => {
  if (provider) {
    return provider;
  }
  provider = new LoggerProvider({
    processors: [new DedupLogRecordProcessor(buildShippingProcessor(isDev), { onSuppressed: reportSuppressed })],
    loggerConfigurator: () => ({
      disabled: false,
      minimumSeverity: isDev ? SEVERITY_NUMBERS.DEBUG : SEVERITY_NUMBERS.INFO,
      traceBased: false,
    }),
  });
  logs.setGlobalLoggerProvider(provider);
  window.addEventListener('error', onUncaughtError);
  window.addEventListener('unhandledrejection', onUnhandledRejection);
  return provider;
};
