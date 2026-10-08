import { describe, expect, it } from 'vitest';
import { errors as elasticErrors } from '@elastic/elasticsearch';
import { errors as openSearchErrors } from '@opensearch-project/opensearch';
import { isEngineUnavailable, wrapEngineError } from '../../../src/database/engine';
import { buildErrorScope } from '../../../src/config/error-origin';
import { DATABASE_ERROR } from '../../../src/config/errors';

const elasticResponse = (statusCode: number, error: Record<string, unknown>) => {
  return new elasticErrors.ResponseError({ statusCode, body: { error }, headers: {}, warnings: null, meta: {} as any });
};
const openSearchResponse = (statusCode: number, error: Record<string, unknown>) => {
  return new openSearchErrors.ResponseError({ statusCode, body: { error }, headers: {} } as any);
};

describe('engine unavailability (RFC 0006)', () => {
  it('should treat a connection failure or a timeout as unavailable', () => {
    expect(isEngineUnavailable(new elasticErrors.ConnectionError('connect ECONNREFUSED'))).toBe(true);
    expect(isEngineUnavailable(new elasticErrors.TimeoutError('Request timed out'))).toBe(true);
    expect(isEngineUnavailable(new elasticErrors.NoLivingConnectionsError('no living connections', {} as any))).toBe(true);
    expect(isEngineUnavailable(new openSearchErrors.ConnectionError('socket hang up', {} as any))).toBe(true);
    expect(isEngineUnavailable(Object.assign(new Error('reset'), { code: 'ECONNRESET' }))).toBe(true);
  });

  it('should treat a failing or overloaded engine as unavailable', () => {
    expect(isEngineUnavailable(elasticResponse(503, { type: 'search_phase_execution_exception', root_cause: [{ type: 'no_shard_available_action_exception' }] }))).toBe(true);
    expect(isEngineUnavailable(elasticResponse(429, { type: 'circuit_breaking_exception' }))).toBe(true);
    expect(isEngineUnavailable(elasticResponse(429, { type: 'es_rejected_execution_exception' }))).toBe(true);
    expect(isEngineUnavailable(openSearchResponse(500, { type: 'exception' }))).toBe(true);
  });

  it('should treat a read-only index (disk watermark) as unavailable, whatever its status', () => {
    expect(isEngineUnavailable(elasticResponse(403, { type: 'cluster_block_exception' }))).toBe(true);
  });

  it('should treat a request we built wrong as a code fault, even on a 5xx', () => {
    expect(isEngineUnavailable(elasticResponse(400, { type: 'parsing_exception' }))).toBe(false);
    expect(isEngineUnavailable(elasticResponse(400, { type: 'search_phase_execution_exception', root_cause: [{ type: 'query_shard_exception' }] }))).toBe(false);
    expect(isEngineUnavailable(elasticResponse(404, { type: 'index_not_found_exception' }))).toBe(false);
    expect(isEngineUnavailable(elasticResponse(409, { type: 'version_conflict_engine_exception' }))).toBe(false);
    expect(isEngineUnavailable(elasticResponse(503, { type: 'search_phase_execution_exception', caused_by: { type: 'too_many_buckets_exception' } }))).toBe(false);
    expect(isEngineUnavailable(new TypeError('x is undefined'))).toBe(false);
  });

  it('should wrap an unavailable engine as an infra error that keeps DATABASE_ERROR', () => {
    const wrapped = wrapEngineError('Fail to execute engine pagination', elasticResponse(429, { type: 'circuit_breaking_exception' }), { query: '{}' });
    expect(wrapped.extensions?.code).toBe(DATABASE_ERROR);
    expect(wrapped.message).toBe('Fail to execute engine pagination');
    expect(buildErrorScope(wrapped, 'catalog')).toEqual({ origin: 'infra', dependency: 'elasticsearch', module: 'catalog', entry_module: 'catalog' });
  });

  it('should wrap a rejected request as a code fault', () => {
    const wrapped = wrapEngineError('Fail to execute engine pagination', elasticResponse(400, { type: 'parsing_exception' }));
    expect(wrapped.extensions?.code).toBe(DATABASE_ERROR);
    expect(buildErrorScope(wrapped, 'catalog')).toEqual({ origin: 'code', module: 'catalog', entry_module: 'catalog' });
  });

  it('should attribute a bug in the engine client code to core', () => {
    const wrapped = wrapEngineError('Fail to execute engine pagination', new TypeError('x is undefined'));
    expect(buildErrorScope(wrapped, 'catalog')).toEqual({ origin: 'code', module: 'core', entry_module: 'catalog' });
  });
});
