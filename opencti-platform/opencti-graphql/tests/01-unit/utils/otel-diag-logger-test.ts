import { afterEach, describe, expect, it, vi } from 'vitest';
import { diag, DiagLogLevel } from '@opentelemetry/api';
import { createOtelDiagLogger, registerOtelDiagLogger } from '../../../src/telemetry/otel-diag-logger';

const buildTarget = () => ({
  error: vi.fn(),
  warn: vi.fn(),
  info: vi.fn(),
  debug: vi.fn(),
});

describe('OpenTelemetry diag logger', () => {
  afterEach(() => {
    diag.disable();
  });

  it('forwards each diag level to the platform logger with a telemetry prefix', () => {
    const target = buildTarget();
    const logger = createOtelDiagLogger(target);
    logger.error('export failed');
    logger.warn('retrying');
    logger.info('started');
    logger.debug('detail');
    logger.verbose('very detailed');
    expect(target.error).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] export failed', {});
    expect(target.warn).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] retrying', {});
    expect(target.info).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] started', {});
    expect(target.debug).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] detail', {});
    expect(target.debug).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] very detailed', {});
  });

  it('keeps the error passed by an exporter as serializable details', () => {
    const target = buildTarget();
    const logger = createOtelDiagLogger(target);
    const cause = new Error('connect ECONNREFUSED 127.0.0.1:4318');
    logger.error('metrics export failed', cause);
    expect(target.error).toHaveBeenCalledTimes(1);
    const [message, meta] = target.error.mock.calls[0];
    expect(message).toBe('[OPENCTI] [TELEMETRY] metrics export failed');
    expect(meta.otel_details[0]).toMatchObject({ name: 'Error', message: 'connect ECONNREFUSED 127.0.0.1:4318' });
  });

  it('routes the global diag API to the platform logger at warn level', () => {
    const target = buildTarget();
    expect(registerOtelDiagLogger(target)).toBe(true);
    diag.error('PeriodicExportingMetricReader: metrics export failed');
    diag.warn('slow export');
    diag.info('ignored info');
    diag.debug('ignored debug');
    expect(target.error).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] PeriodicExportingMetricReader: metrics export failed', {});
    expect(target.warn).toHaveBeenCalledWith('[OPENCTI] [TELEMETRY] slow export', {});
    expect(target.info).not.toHaveBeenCalled();
    expect(target.debug).not.toHaveBeenCalled();
  });

  it('honours an explicit diag level', () => {
    const target = buildTarget();
    registerOtelDiagLogger(target, DiagLogLevel.ERROR);
    diag.warn('dropped');
    diag.error('kept');
    expect(target.warn).not.toHaveBeenCalled();
    expect(target.error).toHaveBeenCalledTimes(1);
  });
});
