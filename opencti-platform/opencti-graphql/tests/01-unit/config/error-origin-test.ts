import { GraphQLError } from 'graphql';
import { describe, expect, it } from 'vitest';
import {
  buildErrorScope,
  classifyErrorOrigin,
  isNetworkFailure,
  levelForOrigin,
  resolveErrorContext,
  resolveErrorModule,
  runWithErrorContext,
  tagErrorModule,
  withErrorContext,
  withModuleApi,
  withModuleTag,
} from '../../../src/config/error-origin';
import { DatabaseError, ForbiddenAccess, FunctionalError, InfraError, UnknownError, UnsupportedError, ValidationError } from '../../../src/config/errors';

// What Apollo hands to the plugins when a resolver throws.
const asResolverError = (e: Error) => new GraphQLError(e.message, { originalError: e });

describe('error origin', () => {
  it('should classify an unknown error as code', () => {
    expect(classifyErrorOrigin(new TypeError('x is undefined'))).toBe('code');
    expect(classifyErrorOrigin(UnknownError('boom'))).toBe('code');
    expect(classifyErrorOrigin(UnsupportedError('unexpected state'))).toBe('code');
    expect(classifyErrorOrigin('a string')).toBe('code');
  });

  it('should classify a typed input error as input', () => {
    expect(classifyErrorOrigin(FunctionalError('bad input'))).toBe('input');
    expect(classifyErrorOrigin(ValidationError('bad field', 'name'))).toBe('input');
    expect(classifyErrorOrigin(ForbiddenAccess())).toBe('input');
    expect(classifyErrorOrigin(asResolverError(FunctionalError('bad input')))).toBe('input');
  });

  it('should classify a typed infra error as infra, whoever wrapped it', () => {
    const infra = InfraError('s3', 'File storage is unavailable');
    expect(classifyErrorOrigin(infra)).toBe('infra');
    expect(classifyErrorOrigin(UnsupportedError('Load file from storage fail', { cause: infra }))).toBe('infra');
    expect(classifyErrorOrigin(FunctionalError('wrapped', { cause: infra }))).toBe('infra');
    expect(classifyErrorOrigin(new Error('native wrapper', { cause: infra }))).toBe('infra');
    expect(classifyErrorOrigin(asResolverError(infra))).toBe('infra');
  });

  it('should classify an error naming its failed dependency as infra, whatever its code', () => {
    const engineDown = DatabaseError('Fail to execute engine pagination', { dependency: 'elasticsearch' });
    expect(buildErrorScope(engineDown)).toEqual({ origin: 'infra', dependency: 'elasticsearch' });
    expect(classifyErrorOrigin(DatabaseError('Bulk indexing fail', { dependency: true }))).toBe('code');
    expect(classifyErrorOrigin(DatabaseError('Bulk indexing fail', { dependency: 'unknown' }))).toBe('code');
  });

  it('should classify an input error rethrown as a bug as code', () => {
    const rejection = FunctionalError('rejected by the other module');
    expect(classifyErrorOrigin(UnknownError('we built invalid data', { cause: rejection }))).toBe('code');
  });

  it('should resolve the dependency of an infra error', () => {
    const scope = buildErrorScope(UnsupportedError('wrapped', { cause: InfraError('s3') }));
    expect(scope).toEqual({ origin: 'infra', dependency: 's3' });
  });

  it('should detect network failures in the chain', () => {
    const refused = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    expect(isNetworkFailure(refused)).toBe(true);
    expect(isNetworkFailure(new Error('wrapper', { cause: refused }))).toBe(true);
    expect(isNetworkFailure(new Error('other'))).toBe(false);
  });
});

describe('error module', () => {
  it('should keep the innermost tag', () => {
    const inner = tagErrorModule(new Error('raised in connector'), 'connector');
    const outer = tagErrorModule(UnknownError('wrapped in catalog', { cause: inner }), 'catalog');
    expect(resolveErrorModule(outer)).toBe('connector');
    expect(resolveErrorModule(asResolverError(outer))).toBe('connector');
  });

  it('should not retag an error that already left a module', () => {
    const e = tagErrorModule(new Error('raised in connector'), 'connector');
    tagErrorModule(e, 'catalog');
    expect(resolveErrorModule(e)).toBe('connector');
  });

  it('should attribute an untagged error to the entry module', () => {
    expect(buildErrorScope(new Error('untagged'), 'catalog')).toEqual({ origin: 'code', module: 'catalog', entry_module: 'catalog' });
  });

  it('should keep both the module and the entry module', () => {
    const e = tagErrorModule(new Error('raised in connector'), 'connector');
    expect(buildErrorScope(e, 'catalog')).toEqual({ origin: 'code', module: 'connector', entry_module: 'catalog' });
  });

  it('should leave code outside any module without a module field', () => {
    expect(buildErrorScope(new Error('untagged'))).toEqual({ origin: 'code' });
  });

  it('should tag errors thrown by a wrapped function', () => {
    const fn = withModuleTag('catalog', () => {
      throw new Error('sync');
    });
    let caught: unknown;
    try {
      fn();
    } catch (e) {
      caught = e;
    }
    expect(resolveErrorModule(caught)).toBe('catalog');
  });

  it('should tag rejections of a wrapped async function', async () => {
    const fn = withModuleTag('catalog', async () => {
      throw new Error('async');
    });
    const caught = await fn().catch((e: unknown) => e);
    expect(resolveErrorModule(caught)).toBe('catalog');
  });

  it('should return the result of a wrapped function untouched', async () => {
    const api = withModuleApi('catalog', {
      sum: (a: number, b: number) => a + b,
      sumAsync: async (a: number, b: number) => a + b,
      LIMIT: 10,
    });
    expect(api.sum(1, 2)).toBe(3);
    await expect(api.sumAsync(1, 2)).resolves.toBe(3);
    expect(api.LIMIT).toBe(10);
  });
});

describe('error context', () => {
  it('should keep the class, message and origin of the error', () => {
    const rejection = FunctionalError('bad input');
    const contextual = withErrorContext(rejection, { catalogId: 'c1' });
    expect(contextual).toBe(rejection);
    expect(contextual.message).toBe('bad input');
    expect(classifyErrorOrigin(contextual)).toBe('input');
    expect(resolveErrorContext(contextual)).toEqual({ catalogId: 'c1' });
  });

  it('should keep a key set closer to the failure', () => {
    const e = withErrorContext(new Error('raised'), { contractId: 'inner' });
    withErrorContext(e, { contractId: 'outer', catalogId: 'c1' });
    expect(resolveErrorContext(e)).toEqual({ contractId: 'inner', catalogId: 'c1' });
  });

  it('should merge the context of the whole chain, the innermost winning', () => {
    const inner = withErrorContext(InfraError('elasticsearch'), { index: 'opencti_internal_objects', catalogId: 'inner' });
    const outer = withErrorContext(UnknownError('wrapped', { cause: inner }), { catalogId: 'outer', step: 'upsert' });
    expect(resolveErrorContext(asResolverError(outer))).toEqual({ index: 'opencti_internal_objects', catalogId: 'inner', step: 'upsert' });
  });

  it('should not send the context to GraphQL clients', () => {
    const e = withErrorContext(FunctionalError('bad input'), { catalogId: 'c1' });
    expect(JSON.stringify(e.toJSON())).not.toContain('c1');
  });

  it('should add context to what a call rejects with', async () => {
    const caught = await runWithErrorContext({ catalogId: 'c1' }, async () => {
      throw new Error('write failed');
    }).catch((e: unknown) => e);
    expect(resolveErrorContext(caught)).toEqual({ catalogId: 'c1' });
  });

  it('should leave an error without context undefined', () => {
    expect(resolveErrorContext(new Error('plain'))).toBeUndefined();
  });

  it('should record the public API function an error left through', async () => {
    const api = withModuleApi('catalog', {
      findContract: async () => {
        throw new Error('not reachable');
      },
    });
    const caught = await api.findContract().catch((e: unknown) => e);
    expect(resolveErrorContext(caught)).toEqual({ api: 'catalog.findContract' });
  });

  it('should keep the innermost API function when an error crosses several modules', async () => {
    const connectorApi = withModuleApi('connector', {
      upgrade: async () => {
        throw new Error('raised in connector');
      },
    });
    const catalogApi = withModuleApi('catalog', {
      sync: async () => connectorApi.upgrade(),
    });
    const caught = await catalogApi.sync().catch((e: unknown) => e);
    expect(resolveErrorContext(caught)).toEqual({ api: 'connector.upgrade' });
    expect(resolveErrorModule(caught)).toBe('connector');
  });
});

describe('error level', () => {
  it('should log a code fault at error', () => {
    expect(levelForOrigin('code')).toBe('error');
  });

  it('should log a dependency failure and rejected input at warn', () => {
    expect(levelForOrigin('infra')).toBe('warn');
    expect(levelForOrigin('input')).toBe('warn');
  });
});
