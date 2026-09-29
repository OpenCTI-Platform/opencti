import { beforeEach, afterEach, describe, expect, it } from 'vitest';
import { logs } from '@opentelemetry/api-logs';
import { InMemoryLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { DedupLogRecordProcessor } from './DedupLogRecordProcessor';
import { toFrontendLogInput } from './GraphQLLogRecordExporter';
import { SEVERITY_NUMBERS, logger } from './logger';

describe('logger pipeline', () => {
  let exporter: InMemoryLogRecordExporter;
  let provider: LoggerProvider;

  beforeEach(() => {
    exporter = new InMemoryLogRecordExporter();
    provider = new LoggerProvider({
      processors: [new DedupLogRecordProcessor(new SimpleLogRecordProcessor({ exporter }))],
      loggerConfigurator: () => ({ disabled: false, minimumSeverity: SEVERITY_NUMBERS.INFO, traceBased: false }),
    });
    logs.setGlobalLoggerProvider(provider);
  });

  afterEach(async () => {
    await provider.shutdown();
    logs.disable();
  });

  it('carries message, event name and data through to the exporter payload', () => {
    logger.warn('Filter value is not a string', {
      eventName: 'opencti.filter.value_not_string',
      data: { filter: { key: 'objectLabel' } },
    });

    const [record] = exporter.getFinishedLogRecords();
    expect(toFrontendLogInput(record)).toMatchObject({
      level: 'WARN',
      message: 'Filter value is not a string',
      eventName: 'opencti.filter.value_not_string',
      data: { filter: { key: 'objectLabel' } },
      exception: null,
    });
  });

  it('maps a thrown error onto the exception fields', () => {
    logger.error('React component tree crashed', {
      eventName: 'opencti.frontend.component_crashed',
      error: new TypeError('value.split is not a function'),
    });

    const [record] = exporter.getFinishedLogRecords();
    const { exception } = toFrontendLogInput(record);
    expect(exception?.type).toBe('TypeError');
    expect(exception?.message).toBe('value.split is not a function');
    expect(exception?.stacktrace).toContain('TypeError: value.split is not a function');
  });
});
