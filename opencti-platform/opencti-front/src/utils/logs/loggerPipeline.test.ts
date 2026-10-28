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

  it.each([
    ['undefined', undefined, '[object Undefined]'],
    ['a plain object', { reason: 'nope' }, '[object Object]'],
    ['a null-prototype object', Object.create(null), '[object Object]'],
    ['a DOM Event', new Event('error'), '[object Event]'],
  ])('wraps %s thrown into an Error that names its type', (_label, thrown, type) => {
    logger.error('Unhandled promise rejection', {
      eventName: 'opencti.frontend.unhandled_rejection',
      error: thrown,
    });

    const [record] = exporter.getFinishedLogRecords();
    const { exception } = toFrontendLogInput(record);
    expect(exception?.type).toBe('Error');
    expect(exception?.message).toBe(`Non-Error value thrown: ${type}`);
  });

  it('normalizes non-plain data values instead of dropping the attribute', () => {
    logger.warn('Filter value is not a string', {
      eventName: 'opencti.filter.value_not_string',
      data: { at: new Date('2026-10-28T00:00:00.000Z'), cause: new RangeError('out of range') },
    });

    const [record] = exporter.getFinishedLogRecords();
    expect(toFrontendLogInput(record).data).toEqual({
      at: '2026-10-28T00:00:00.000Z',
      cause: { name: 'RangeError', message: 'out of range' },
    });
  });

  it('marks data that cannot be serialized', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    logger.warn('Filter value is not a string', { eventName: 'opencti.filter.value_not_string', data: cyclic });

    const [record] = exporter.getFinishedLogRecords();
    expect(toFrontendLogInput(record).data).toEqual({ unserializable: true });
  });

  it('leaves the exception empty when no error is given', () => {
    logger.warn('Filter value is not a string', { eventName: 'opencti.filter.value_not_string' });

    const [record] = exporter.getFinishedLogRecords();
    expect(toFrontendLogInput(record).exception).toBeNull();
  });
});
