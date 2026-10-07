import { GraphQLError } from 'graphql';
import { describe, expect, it } from 'vitest';
import {
  buildErrorScope,
  classifyErrorOrigin,
  isNetworkFailure,
  levelForOrigin,
  resolveErrorModule,
  tagErrorModule,
  withModuleApi,
  withModuleTag,
} from '../../../src/config/error-origin';
import { ForbiddenAccess, FunctionalError, InfraError, UnknownError, UnsupportedError, ValidationError } from '../../../src/config/errors';

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

describe('error level', () => {
  it('should log a code fault at error', () => {
    expect(levelForOrigin('code')).toBe('error');
  });

  it('should log a dependency failure and rejected input at warn', () => {
    expect(levelForOrigin('infra')).toBe('warn');
    expect(levelForOrigin('input')).toBe('warn');
  });
});
