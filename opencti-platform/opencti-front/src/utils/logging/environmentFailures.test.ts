import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logs } from '@opentelemetry/api';
import { InMemoryLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from '@opentelemetry/sdk-logs';
import {
  CHUNK_LOAD_FAILED_EVENT_NAME,
  CHUNK_RELOAD_COOLDOWN_MS,
  CHUNK_RELOAD_EVENT_NAME,
  CHUNK_RELOAD_STORAGE_KEY,
  NETWORK_FAILED_EVENT_NAME,
  claimChunkReload,
  isChunkLoadError,
  isNetworkFailure,
  reloadOnceForChunkError,
  warnIfEnvironmentFailure,
} from './environmentFailures';
import { SEVERITY_NUMBERS } from './logger';

const CHUNK_URL = 'https://platform.example/assets/Root-AbCd1234.js';

beforeEach(() => {
  sessionStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('isChunkLoadError', () => {
  it.each([
    ['Chrome', new TypeError(`Failed to fetch dynamically imported module: ${CHUNK_URL}`)],
    ['Firefox', new TypeError(`error loading dynamically imported module: ${CHUNK_URL}`)],
    ['Safari', new TypeError('Importing a module script failed.')],
    ['the Vite preload helper', new Error('Unable to preload CSS for /assets/Root-AbCd1234.css')],
  ])('matches the error raised by %s', (_source, error) => {
    expect(isChunkLoadError(error)).toBe(true);
  });

  it('matches the message of an uncaught error event that carries no error object', () => {
    expect(isChunkLoadError(`Uncaught TypeError: Failed to fetch dynamically imported module: ${CHUNK_URL}`)).toBe(true);
  });

  it.each([
    ['a network failure', new TypeError('Failed to fetch')],
    ['a component bug', new TypeError("Cannot read properties of undefined (reading 'default')")],
    ['undefined', undefined],
    ['a plain object', { message: 'Failed to fetch dynamically imported module' }],
  ])('does not match %s', (_label, error) => {
    expect(isChunkLoadError(error)).toBe(false);
  });
});

describe('isNetworkFailure', () => {
  it.each([
    ['Chrome', 'Failed to fetch'],
    ['Firefox', 'NetworkError when attempting to fetch resource.'],
    ['Safari', 'Load failed'],
  ])('matches the fetch rejection raised by %s', (_browser, message) => {
    expect(isNetworkFailure(new TypeError(message))).toBe(true);
  });

  it.each([
    ['a chunk load error', new TypeError(`Failed to fetch dynamically imported module: ${CHUNK_URL}`)],
    ['the same message on another error type', new Error('Failed to fetch')],
    ['a message string', 'Failed to fetch'],
    ['a component bug', new TypeError('value.split is not a function')],
  ])('does not match %s', (_label, error) => {
    expect(isNetworkFailure(error)).toBe(false);
  });
});

describe('claimChunkReload', () => {
  const now = 1_700_000_000_000;

  it('claims the first reload and records when it happened', () => {
    expect(claimChunkReload(now)).toBe(true);
    expect(sessionStorage.getItem(CHUNK_RELOAD_STORAGE_KEY)).toBe(String(now));
  });

  it('refuses another reload within the cooldown, so a still missing chunk cannot loop', () => {
    expect(claimChunkReload(now)).toBe(true);
    expect(claimChunkReload(now + CHUNK_RELOAD_COOLDOWN_MS - 1)).toBe(false);
    expect(sessionStorage.getItem(CHUNK_RELOAD_STORAGE_KEY)).toBe(String(now));
  });

  it('claims a reload again once the cooldown is over', () => {
    expect(claimChunkReload(now)).toBe(true);
    expect(claimChunkReload(now + CHUNK_RELOAD_COOLDOWN_MS)).toBe(true);
  });

  it('ignores an unreadable stored value', () => {
    sessionStorage.setItem(CHUNK_RELOAD_STORAGE_KEY, 'not-a-timestamp');
    expect(claimChunkReload(now)).toBe(true);
  });

  it('does not reload when storage is unavailable, since nothing could stop a loop', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('Storage is disabled', 'SecurityError');
    });
    expect(claimChunkReload(now)).toBe(false);
  });

  it('does not reload when the timestamp cannot be stored', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Quota exceeded', 'QuotaExceededError');
    });
    expect(claimChunkReload(now)).toBe(false);
  });
});

describe('logging', () => {
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

  describe('reloadOnceForChunkError', () => {
    it('reloads once and logs the reload at info', () => {
      const reload = vi.fn();
      const error = new TypeError(`Failed to fetch dynamically imported module: ${CHUNK_URL}`);

      expect(reloadOnceForChunkError(error, reload)).toBe(true);
      expect(reloadOnceForChunkError(error, reload)).toBe(false);

      expect(reload).toHaveBeenCalledTimes(1);
      const records = exporter.getFinishedLogRecords();
      expect(records).toHaveLength(1);
      expect(records[0].eventName).toBe(CHUNK_RELOAD_EVENT_NAME);
      expect(records[0].severityNumber).toBe(SEVERITY_NUMBERS.INFO);
    });
  });

  describe('warnIfEnvironmentFailure', () => {
    it('logs a chunk load error at warn with its own event name', () => {
      expect(warnIfEnvironmentFailure(new TypeError('Importing a module script failed.'), { source: 'test' })).toBe(true);

      const [record] = exporter.getFinishedLogRecords();
      expect(record.eventName).toBe(CHUNK_LOAD_FAILED_EVENT_NAME);
      expect(record.severityNumber).toBe(SEVERITY_NUMBERS.WARN);
      expect(record.attributes.data).toEqual({ source: 'test' });
    });

    it('logs a network failure at warn with its own event name', () => {
      expect(warnIfEnvironmentFailure(new TypeError('Failed to fetch'))).toBe(true);

      const [record] = exporter.getFinishedLogRecords();
      expect(record.eventName).toBe(NETWORK_FAILED_EVENT_NAME);
      expect(record.severityNumber).toBe(SEVERITY_NUMBERS.WARN);
    });

    it('leaves any other error to the caller, without logging', () => {
      expect(warnIfEnvironmentFailure(new TypeError('value.split is not a function'))).toBe(false);
      expect(exporter.getFinishedLogRecords()).toHaveLength(0);
    });
  });
});
