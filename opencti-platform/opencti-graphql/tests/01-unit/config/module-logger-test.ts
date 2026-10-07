import { afterEach, describe, expect, it, vi } from 'vitest';
import { logApp, prepareLogMetadata } from '../../../src/config/conf';
import { DatabaseError, FunctionalError, InfraError, UnknownError } from '../../../src/config/errors';
import { tagErrorModule, withErrorContext } from '../../../src/config/error-origin';
import { bestEffort, createModuleLogger, logBoundaryError } from '../../../src/config/module-logger';

describe('module logger', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should add the module to every record', () => {
    const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
    createModuleLogger('catalog').warn('Something degraded', { catalogId: 'c1' });
    expect(warn).toHaveBeenCalledWith('Something degraded', { catalogId: 'c1', module: 'catalog' });
  });

  it('should not let the caller override the module', () => {
    const info = vi.spyOn(logApp, 'info').mockImplementation(() => {});
    createModuleLogger('catalog').info('Message', { module: 'connector' });
    expect(info).toHaveBeenCalledWith('Message', { module: 'catalog' });
  });
});

describe('boundary logger', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should log a code fault at error with its scope', () => {
    const log = vi.spyOn(logApp, 'error').mockImplementation(() => {});
    const error = tagErrorModule(new TypeError('x is undefined'), 'connector');
    const scope = logBoundaryError('Catalog Manager handling error', error, { manager: 'CATALOG_MANAGER', entryModule: 'catalog' });
    expect(scope).toEqual({ origin: 'code', module: 'connector', entry_module: 'catalog' });
    expect(log).toHaveBeenCalledWith('Catalog Manager handling error', {
      manager: 'CATALOG_MANAGER',
      origin: 'code',
      module: 'connector',
      entry_module: 'catalog',
      cause: error,
    });
  });

  it('should log a dependency failure at warn, even for the platform own storage', () => {
    const log = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
    const error = UnknownError('wrapped', { cause: InfraError('s3') });
    logBoundaryError('Upload failed', error, { entryModule: 'catalog' });
    expect(log).toHaveBeenCalledWith('Upload failed', expect.objectContaining({ origin: 'infra', dependency: 's3', module: 'catalog' }));
  });

  it('should log rejected input at warn', () => {
    const log = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
    logBoundaryError('Invalid request', FunctionalError('bad input'), { entryModule: 'catalog' });
    expect(log).toHaveBeenCalledWith('Invalid request', expect.objectContaining({ origin: 'input', module: 'catalog' }));
  });

  it('should log the context the error picked up under error_context', () => {
    const log = vi.spyOn(logApp, 'error').mockImplementation(() => {});
    const error = withErrorContext(new TypeError('x is undefined'), { catalogId: 'c1' });
    logBoundaryError('Sync failed', error, { entryModule: 'catalog' });
    expect(log).toHaveBeenCalledWith('Sync failed', expect.objectContaining({ error_context: { catalogId: 'c1' }, origin: 'code' }));
  });

  // The output format: what reaches the transports.
  it('should produce a record carrying the RFC 0006 fields', () => {
    const error = tagErrorModule(InfraError('s3', 'File storage is unavailable'), 'core');
    const log = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
    logBoundaryError('Upload failed', error, { entryModule: 'catalog' });
    const [, meta] = log.mock.calls[0];
    const record = prepareLogMetadata(meta, { category: 'APP', source: 'backend' });
    expect(record).toMatchObject({
      category: 'APP',
      source: 'backend',
      module: 'core',
      entry_module: 'catalog',
      origin: 'infra',
      dependency: 's3',
      cause: { name: 'INFRA_ERROR', code: 'INFRA_ERROR', message: 'File storage is unavailable', attributes: { dependency: 's3' } },
    });
    expect(record.version).toBeDefined();
  });
});

describe('best effort', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return the result of a successful operation', async () => {
    await expect(bestEffort('push_auth_log', async () => 'pushed')).resolves.toBe('pushed');
  });

  it('should log an unavailable dependency at warn and continue', async () => {
    const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
    const result = await bestEffort('push_auth_log', async () => {
      throw DatabaseError('Redis transaction error', { dependency: 'redis' });
    }, { type: 'OIDC' });
    expect(result).toBeUndefined();
    expect(warn).toHaveBeenCalledWith('[BEST-EFFORT] Operation failed, continuing', expect.objectContaining({
      operation: 'push_auth_log',
      type: 'OIDC',
      origin: 'infra',
      dependency: 'redis',
    }));
  });

  it('should still log a bug at error', async () => {
    const error = vi.spyOn(logApp, 'error').mockImplementation(() => {});
    await bestEffort('push_auth_log', async () => {
      throw new TypeError('x is undefined');
    });
    expect(error).toHaveBeenCalledWith('[BEST-EFFORT] Operation failed, continuing', expect.objectContaining({ origin: 'code' }));
  });
});
