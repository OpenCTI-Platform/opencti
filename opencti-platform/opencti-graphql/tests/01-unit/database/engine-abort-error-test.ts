import { describe, expect, it } from 'vitest';
import { AbortError } from 'node-fetch';
import { errors as openSearchErrors } from '@opensearch-project/opensearch';
import { wrapEngineError } from '../../../src/database/engine';
import { CLIENT_ABORT_ERROR, DATABASE_ERROR } from '../../../src/config/errors';

// wrapEngineError is the single, shared classification point used by every
// call site that catches an error from an abort-signal-aware engine
// operation (elRawSearch, elUpdate, ...): elFindByIds, elPaginate,
// elCardinality, elAggregations*, elUpdate (src/database/engine.ts) and
// inconsistencyCleaner.ts's loadRawElement. A client/proxy disconnect (or a
// killed pod) that aborts the request before Elasticsearch is even reached
// must be classified distinctly from a genuine engine/ES failure, so it
// isn't logged at the same severity (see loggerPlugin.js + config/errors.js).
describe('wrapEngineError testing', () => {
  it('should classify an abort-before-request error as CLIENT_ABORT_ERROR, not DATABASE_ERROR', () => {
    const abortCause = new AbortError('The http call was aborted before el request started.');

    const wrapped = wrapEngineError('Fail to execute engine pagination', abortCause, { query: {} });

    expect(wrapped.extensions?.code).toBe(CLIENT_ABORT_ERROR);
    expect(wrapped.extensions?.code).not.toBe(DATABASE_ERROR);
  });

  it('should keep classifying a genuine engine failure as DATABASE_ERROR', () => {
    const engineCause = new Error('circuit_breaking_exception');

    const wrapped = wrapEngineError('Fail to execute engine pagination', engineCause, { query: {} });

    expect(wrapped.extensions?.code).toBe(DATABASE_ERROR);
  });

  it('should classify a write-path abort (e.g. elUpdate) the same way as a search-path abort', () => {
    // Same failure mode, different call site (elUpdate's catch block),
    // proving the classification isn't accidentally search-specific.
    const abortCause = new AbortError('The http call was aborted before el request started.');

    const wrapped = wrapEngineError('Update indexing fail', abortCause, { documentId: 'id-1', entityType: 'Malware' });

    expect(wrapped.extensions?.code).toBe(CLIENT_ABORT_ERROR);
  });

  it('should preserve the cause and extra contextual data passed by the caller', () => {
    const abortCause = new AbortError('The http call was aborted before el request started.');

    const wrapped = wrapEngineError('Find direct ids fail', abortCause, { searchType: 'Malware' });

    const data = wrapped.extensions?.data as Record<string, any>;
    expect(data.cause).toBe(abortCause);
    expect(data.searchType).toBe('Malware');
  });

  it('should not misclassify a plain object without a name property as a client abort', () => {
    const wrapped = wrapEngineError('Fail to execute engine pagination', { message: 'timeout' }, {});

    expect(wrapped.extensions?.code).toBe(DATABASE_ERROR);
  });

  it('should classify OpenSearch client aborts (RequestAbortedError) as CLIENT_ABORT_ERROR too', () => {
    // real error class, not a guessed shape — its name isn't 'AbortError'
    const abortCause = new openSearchErrors.RequestAbortedError('Request aborted');

    const wrapped = wrapEngineError('Fail to execute engine pagination', abortCause, {});

    expect(wrapped.extensions?.code).toBe(CLIENT_ABORT_ERROR);
    expect(wrapped.extensions?.code).not.toBe(DATABASE_ERROR);
  });
});
