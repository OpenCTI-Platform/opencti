import { describe, expect, it } from 'vitest';
import {
  elAggregationCount,
  elAggregationNestedTermsWithFilter,
  elAggregationRelationsCount,
  elAggregationsList,
  elCardinalityCount,
  elFindByIds,
  elHistogramCount,
  elPaginate,
  elUpdate,
} from '../../../src/database/engine';
import { cleanAllEntityInconsistencies } from '../../../src/database/inconsistencyCleaner';
import { CLIENT_ABORT_ERROR, DATABASE_ERROR } from '../../../src/config/errors';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { READ_DATA_INDICES_WITHOUT_INFERRED, READ_ENTITIES_INDICES, READ_INDEX_HISTORY, READ_RELATIONSHIPS_INDICES } from '../../../src/database/utils';

// elExecuteWithAbortSignal (see src/database/engine.ts) throws AbortError as
// soon as context.requestAbortSignal is already aborted, before Elasticsearch
// is ever called. These tests build a real, already-aborted context and run
// it through the actual functions (no mocking of the engine module) to prove
// every call site classifies that failure as CLIENT_ABORT_ERROR, not
// DATABASE_ERROR, end to end.
const abortedContext = () => ({ ...testContext, requestAbortSignal: AbortSignal.abort() });

describe('Engine calls classify an already-aborted request as CLIENT_ABORT_ERROR', () => {
  it('elFindByIds should reject with CLIENT_ABORT_ERROR', async () => {
    await expect(elFindByIds(abortedContext(), ADMIN_USER, 'engine-abort-test-id'))
      .rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
  });

  it('elPaginate should reject with CLIENT_ABORT_ERROR', async () => {
    await expect(elPaginate(abortedContext(), ADMIN_USER, READ_ENTITIES_INDICES, {}))
      .rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
  });

  it('elCardinalityCount should reject with CLIENT_ABORT_ERROR', async () => {
    await expect(elCardinalityCount(abortedContext(), ADMIN_USER, READ_INDEX_HISTORY, 'internal_id'))
      .rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
  });

  it('elAggregationsList should reject with CLIENT_ABORT_ERROR', async () => {
    await expect(elAggregationsList(abortedContext(), ADMIN_USER, READ_DATA_INDICES_WITHOUT_INFERRED, [{ field: 'entity_type.keyword', name: 'entity_type' }]))
      .rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
  });

  it('elAggregationCount should reject with CLIENT_ABORT_ERROR', async () => {
    await expect(elAggregationCount(abortedContext(), ADMIN_USER, READ_DATA_INDICES_WITHOUT_INFERRED, { field: 'entity_type' }))
      .rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
  });

  it('elAggregationRelationsCount should reject with CLIENT_ABORT_ERROR', async () => {
    await expect(elAggregationRelationsCount(abortedContext(), ADMIN_USER, READ_RELATIONSHIPS_INDICES, { field: 'entity_type' }))
      .rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
  });

  it('elAggregationNestedTermsWithFilter should reject with CLIENT_ABORT_ERROR', async () => {
    const aggregation = { path: 'connections', field: 'connections.internal_id.keyword', filter: { match_all: {} } };
    await expect(elAggregationNestedTermsWithFilter(abortedContext(), ADMIN_USER, READ_RELATIONSHIPS_INDICES, aggregation))
      .rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
  });

  it('elHistogramCount should reject with CLIENT_ABORT_ERROR', async () => {
    await expect(elHistogramCount(abortedContext(), ADMIN_USER, READ_DATA_INDICES_WITHOUT_INFERRED, { field: 'created_at', interval: 'month' }))
      .rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
  });

  it('elUpdate (write path) should reject with CLIENT_ABORT_ERROR', async () => {
    await expect(elUpdate(abortedContext(), READ_ENTITIES_INDICES[0], 'engine-abort-test-id', { doc: {} }))
      .rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
  });

  it('cleanAllEntityInconsistencies (inconsistencyCleaner.loadRawElement) should reject with CLIENT_ABORT_ERROR', async () => {
    await expect(cleanAllEntityInconsistencies(abortedContext(), ADMIN_USER, 'engine-abort-test-id'))
      .rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
  });
});

describe('Engine calls keep classifying a genuine engine failure as DATABASE_ERROR', () => {
  it('elAggregationNestedTermsWithFilter should reject with DATABASE_ERROR on an invalid query', async () => {
    const aggregation = { path: 'connections', field: 'connections.internal_id.keyword', filter: { not_a_query: {} } };
    await expect(elAggregationNestedTermsWithFilter(testContext, ADMIN_USER, READ_RELATIONSHIPS_INDICES, aggregation))
      .rejects.toMatchObject({ extensions: { code: DATABASE_ERROR } });
  });
});
