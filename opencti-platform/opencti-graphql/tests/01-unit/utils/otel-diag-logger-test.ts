import { afterEach, describe, expect, it, vi } from 'vitest';
import { diag, DiagLogLevel } from '@opentelemetry/api';
import { createOtelDiagLogger, registerOtelDiagLogger, sanitizeExporterUrl } from '../../../src/telemetry/otel-diag-logger';

const buildTarget = () => ({
  error: vi.fn(),
  warn: vi.fn(),
  info: vi.fn(),
  debug: vi.fn(),
});

// The shape the SDK readers and span processors use: globalErrorHandler calls
// diag.error(JSON.stringify(exception)), one serialized exception and no extra argument.
const serializedException = (message: string) => JSON.stringify({
  message,
  stack: `Error: ${message}\n    at currentRun (PeriodicExportingMetricReader.cjs:88:96)`,
});

const UNAUTHORIZED = 'PeriodicExportingMetricReader: metrics export failed (error OTLPExporterError: Unauthorized)';

describe('OpenTelemetry diag logger', () => {
  afterEach(() => {
    diag.disable();
  });

  it('forwards info, debug and verbose with a telemetry prefix', () => {
    const target = buildTarget();
    const logger = createOtelDiagLogger(target);
    logger.info('started');
    logger.debug('detail');
    logger.verbose('very detailed');
    expect(target.info).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] started', {});
    expect(target.debug).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] detail', {});
    expect(target.debug).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] very detailed', {});
  });

  it('logs export failures at warn, never error', () => {
    const target = buildTarget();
    const logger = createOtelDiagLogger(target);
    logger.error('export failed');
    logger.warn('retrying');
    expect(target.error).not.toHaveBeenCalled();
    expect(target.warn).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] export failed', {});
    expect(target.warn).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] retrying', {});
  });

  it('keeps the message of a serialized exception and moves its stack to metadata', () => {
    const target = buildTarget();
    const logger = createOtelDiagLogger(target);
    logger.error(serializedException(UNAUTHORIZED));
    expect(target.warn).toHaveBeenCalledTimes(1);
    const [message, meta] = target.warn.mock.calls[0];
    expect(message).toBe(`[OPENCTI] [TELEMETRY] ${UNAUTHORIZED}`);
    expect(meta.otel_error.stack).toContain('PeriodicExportingMetricReader.cjs');
  });

  it('adds the unreachable-collector hint to an export timeout', () => {
    const target = buildTarget();
    const logger = createOtelDiagLogger(target);
    logger.error(serializedException('PeriodicExportingMetricReader: metrics export timed out after 1000ms'));
    const [message] = target.warn.mock.calls[0];
    expect(message).toContain('metrics export timed out after 1000ms');
    expect(message).toContain('the collector is unreachable');
  });

  it('logs a repeated failure once per window with the count of suppressed records', () => {
    const target = buildTarget();
    let time = 0;
    const logger = createOtelDiagLogger(target, { throttleMs: 60_000, now: () => time });
    for (let i = 0; i < 15; i += 1) {
      time = i * 1000;
      logger.error(serializedException(UNAUTHORIZED));
    }
    expect(target.warn).toHaveBeenCalledTimes(1);
    time = 61_000;
    logger.error(serializedException(UNAUTHORIZED));
    expect(target.warn).toHaveBeenCalledTimes(2);
    expect(target.warn.mock.calls[1][1].otel_suppressed_count).toBe(14);
  });

  it('throttles each distinct failure on its own', () => {
    const target = buildTarget();
    const logger = createOtelDiagLogger(target, { throttleMs: 60_000, now: () => 0 });
    logger.error(serializedException(UNAUTHORIZED));
    logger.error(serializedException('PeriodicExportingMetricReader: metrics export failed (error OTLPExporterError: Not Found)'));
    logger.error(serializedException(UNAUTHORIZED));
    expect(target.warn).toHaveBeenCalledTimes(2);
  });

  it('keeps an error passed as an argument as serializable details', () => {
    const target = buildTarget();
    const logger = createOtelDiagLogger(target);
    logger.warn('export failed', new Error('connect ECONNREFUSED 127.0.0.1:4318'));
    const [, meta] = target.warn.mock.calls[0];
    expect(meta.otel_details[0]).toMatchObject({ name: 'Error', message: 'connect ECONNREFUSED 127.0.0.1:4318' });
  });

  it('routes the global diag API to the platform logger at warn level', () => {
    const target = buildTarget();
    expect(registerOtelDiagLogger(target)).toBe(true);
    diag.error(serializedException(UNAUTHORIZED));
    diag.info('ignored info');
    diag.debug('ignored debug');
    expect(target.warn).toHaveBeenCalledWith(`[OPENCTI] [TELEMETRY] ${UNAUTHORIZED}`, expect.any(Object));
    expect(target.error).not.toHaveBeenCalled();
    expect(target.info).not.toHaveBeenCalled();
    expect(target.debug).not.toHaveBeenCalled();
  });

  it('honours an explicit diag level', () => {
    const target = buildTarget();
    registerOtelDiagLogger(target, DiagLogLevel.ERROR);
    diag.warn('dropped');
    diag.error('kept');
    expect(target.warn).toHaveBeenCalledTimes(1);
    expect(target.warn).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] kept', {});
  });
});

describe('OpenTelemetry exporter URL sanitizer', () => {
  it('keeps scheme, host, port and path', () => {
    expect(sanitizeExporterUrl('http://collector:4318/v1/metrics')).toBe('http://collector:4318/v1/metrics');
    expect(sanitizeExporterUrl('https://otel.example.com/v1/traces')).toBe('https://otel.example.com/v1/traces');
  });

  it('drops credentials, query string and fragment', () => {
    const sanitized = sanitizeExporterUrl('https://user:s3cret@otel.example.com:4318/v1/traces?api_key=t0ken#frag');
    expect(sanitized).toBe('https://otel.example.com:4318/v1/traces');
    expect(sanitized).not.toContain('s3cret');
    expect(sanitized).not.toContain('t0ken');
    expect(sanitized).not.toContain('user');
  });

  it('never echoes an unparseable or empty value', () => {
    expect(sanitizeExporterUrl('not a url with secret')).toBe('[unparseable URL]');
    expect(sanitizeExporterUrl('')).toBe('');
    expect(sanitizeExporterUrl(undefined)).toBe('');
  });
});
