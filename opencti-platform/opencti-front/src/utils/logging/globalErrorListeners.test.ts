import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { logs } from '@opentelemetry/api';
import { InMemoryLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { onUncaughtError, onUnhandledRejection } from './loggerProvider';
import { CHUNK_LOAD_FAILED_EVENT_NAME, NETWORK_FAILED_EVENT_NAME } from './environmentFailures';
import { SEVERITY_NUMBERS } from './logger';

const rejection = (reason: unknown) => ({ reason }) as PromiseRejectionEvent;

describe('global error listeners', () => {
  let exporter: InMemoryLogRecordExporter;
  let provider: LoggerProvider;

  beforeEach(() => {
    exporter = new InMemoryLogRecordExporter();
    provider = new LoggerProvider({
      processors: [new SimpleLogRecordProcessor({ exporter })],
      loggerConfigurator: () => ({ enabled: true, minimumSeverity: SEVERITY_NUMBERS.DEBUG, traceBased: false }),
    });
    logs.setGlobalLoggerProvider(provider);
  });

  afterEach(async () => {
    await provider.shutdown();
    logs.disable();
  });

  const onlyRecord = () => {
    const records = exporter.getFinishedLogRecords();
    expect(records).toHaveLength(1);
    return records[0];
  };

  it('logs a rejected fetch without response at warn', () => {
    onUnhandledRejection(rejection(new TypeError('NetworkError when attempting to fetch resource.')));

    const record = onlyRecord();
    expect(record.eventName).toBe(NETWORK_FAILED_EVENT_NAME);
    expect(record.severityNumber).toBe(SEVERITY_NUMBERS.WARN);
    expect(record.attributes.data).toEqual({ source: 'unhandled_rejection' });
  });

  it('logs a rejected dynamic import at warn', () => {
    onUnhandledRejection(rejection(new TypeError('error loading dynamically imported module: https://platform.example/assets/Root-AbCd1234.js')));

    const record = onlyRecord();
    expect(record.eventName).toBe(CHUNK_LOAD_FAILED_EVENT_NAME);
    expect(record.severityNumber).toBe(SEVERITY_NUMBERS.WARN);
  });

  it('keeps any other rejection at error', () => {
    onUnhandledRejection(rejection(new RangeError('Invalid time value')));

    const record = onlyRecord();
    expect(record.eventName).toBe('opencti.frontend.unhandled_rejection');
    expect(record.severityNumber).toBe(SEVERITY_NUMBERS.ERROR);
  });

  it('logs an uncaught network failure at warn', () => {
    onUncaughtError(new ErrorEvent('error', { error: new TypeError('Failed to fetch'), message: 'Uncaught TypeError: Failed to fetch' }));

    const record = onlyRecord();
    expect(record.eventName).toBe(NETWORK_FAILED_EVENT_NAME);
    expect(record.severityNumber).toBe(SEVERITY_NUMBERS.WARN);
    expect(record.attributes.data).toEqual({ source: 'uncaught_error' });
  });

  it('keeps any other uncaught error at error', () => {
    onUncaughtError(new ErrorEvent('error', { error: new TypeError('value.split is not a function') }));

    const record = onlyRecord();
    expect(record.eventName).toBe('opencti.frontend.uncaught_error');
    expect(record.severityNumber).toBe(SEVERITY_NUMBERS.ERROR);
  });
});
