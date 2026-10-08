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

  describe('module-scoped classification (RFC 0006)', () => {
    afterEach(() => {
      window.history.pushState({}, '', '/');
    });

    it('carries the origin and the modules of an error through to the exporter payload', () => {
      window.history.pushState({}, '', '/dashboard/integrations/available');
      logger.error('React component tree crashed', {
        eventName: 'opencti.frontend.component_crashed',
        error: new TypeError('value.split is not a function'),
      });

      const [record] = exporter.getFinishedLogRecords();
      expect(toFrontendLogInput(record)).toMatchObject({ origin: 'code', module: 'catalog', entryModule: 'catalog', dependency: null });
    });

    it('attributes the error to the module given by a module boundary', () => {
      window.history.pushState({}, '', '/dashboard/integrations/deployed');
      logger.error('React component tree crashed', {
        eventName: 'opencti.frontend.component_crashed',
        error: new TypeError('value.split is not a function'),
        module: 'catalog',
      });

      const [record] = exporter.getFinishedLogRecords();
      expect(toFrontendLogInput(record)).toMatchObject({ module: 'catalog', entryModule: 'connector' });
    });

    it('names the dependency of an infra failure', () => {
      logger.error('Uncaught error', {
        eventName: 'opencti.frontend.uncaught_error',
        error: new TypeError('Failed to fetch dynamically imported module: https://opencti/static/x.js'),
      });

      const [record] = exporter.getFinishedLogRecords();
      expect(toFrontendLogInput(record)).toMatchObject({ origin: 'infra', dependency: 'assets', module: null, entryModule: null });
    });

    it('leaves a record without error unclassified', () => {
      logger.warn('Filter value is not a string', { eventName: 'opencti.filter.value_not_string' });

      const [record] = exporter.getFinishedLogRecords();
      expect(toFrontendLogInput(record)).toMatchObject({ origin: null, dependency: null });
    });

    it('does not merge the same error raised in two modules', () => {
      const error = new TypeError('value.split is not a function');
      logger.error('React component tree crashed', { eventName: 'opencti.frontend.component_crashed', error, module: 'catalog' });
      logger.error('React component tree crashed', { eventName: 'opencti.frontend.component_crashed', error, module: 'connector' });

      expect(exporter.getFinishedLogRecords().map((record) => toFrontendLogInput(record).module)).toEqual(['catalog', 'connector']);
    });
  });
});
