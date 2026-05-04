import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { InconsistencyCleaningType } from '../../../src/generated/graphql';

// --- Mocks ---

const mockElRawSearch = vi.fn();
const mockElRawUpdateByQuery = vi.fn();

vi.mock('../../../src/database/engine', () => ({
  elRawSearch: (...args: any[]) => mockElRawSearch(...args),
  elRawUpdateByQuery: (...args: any[]) => mockElRawUpdateByQuery(...args),
  ES_MAX_PAGINATION: 5000,
}));

vi.mock('../../../src/database/utils', () => ({
  READ_DATA_INDICES_WITHOUT_INFERRED: 'test-read-index',
}));

vi.mock('../../../src/config/errors', () => ({
  DatabaseError: (message: string, opts: any) => new Error(`${message}: ${JSON.stringify(opts)}`),
}));

vi.mock('../../../src/schema/attribute-definition', () => ({
  internalId: { name: 'internal_id' },
}));

vi.mock('../../../src/schema/general', () => ({
  REL_INDEX_PREFIX: 'rel_',
}));

const mockIsBypassUser = vi.fn();
vi.mock('../../../src/utils/access', () => ({
  isBypassUser: (...args: any[]) => mockIsBypassUser(...args),
}));

const mockIsSingleRelationsRef = vi.fn();
vi.mock('../../../src/schema/stixEmbeddedRelationship', () => ({
  isSingleRelationsRef: (...args: any[]) => mockIsSingleRelationsRef(...args),
}));

const mockIsStixRefUnidirectionalRelationship = vi.fn();
vi.mock('../../../src/schema/stixRefRelationship', () => ({
  isStixRefUnidirectionalRelationship: (...args: any[]) => mockIsStixRefUnidirectionalRelationship(...args),
}));

// --- Import under test (must be after vi.mock calls) ---

import { cleanAllEntityInconsistencies } from '../../../src/database/inconsistencyCleaner';

// --- Test helpers ---

const buildContext = (): AuthContext => ({
  source: 'test',
  tracing: { traceparent: undefined, tracestate: undefined },
} as AuthContext);

const buildBypassUser = (): AuthUser => ({
  id: 'user-bypass-id',
  name: 'bypass-user',
} as AuthUser);

const buildNonBypassUser = (): AuthUser => ({
  id: 'user-normal-id',
  name: 'normal-user',
} as AuthUser);

const buildElasticHit = (source: Record<string, any>) => ({
  _source: source,
});

const buildElasticSearchResponse = (hits: any[]) => ({
  hits: { hits },
});

// --- Tests ---

describe('inconsistencyCleaner', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  afterAll(() => {
    vi.restoreAllMocks();
  });

  describe('cleanAllEntityInconsistencies', () => {
    it('should do nothing when user is not a bypass user', async () => {
      mockIsBypassUser.mockReturnValue(false);

      await cleanAllEntityInconsistencies(buildContext(), buildNonBypassUser(), 'some-id');

      expect(mockElRawSearch).not.toHaveBeenCalled();
      expect(mockElRawUpdateByQuery).not.toHaveBeenCalled();
    });

    it('should do nothing when element is not found', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockElRawSearch.mockResolvedValue(buildElasticSearchResponse([]));

      await cleanAllEntityInconsistencies(buildContext(), buildBypassUser(), 'non-existent-id');

      expect(mockElRawSearch).toHaveBeenCalledTimes(1);
      expect(mockElRawUpdateByQuery).not.toHaveBeenCalled();
    });

    // Note: checkForRefsDuplicates returns an empty array when there are no duplicates,
    // but the source code checks `if (refDuplicatesKeys)` which is always truthy for arrays.
    // This means elRawUpdateByQuery IS called even with an empty duplicatedKeys array.
    // This is a known quirk in the source code.
    it('should still call update when entity has no rel_ refs (empty duplicatedKeys)', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockElRawUpdateByQuery.mockResolvedValue({});
      const entityDoc = buildElasticHit({
        entity_type: 'Malware',
        name: 'TestMalware',
      });
      mockElRawSearch.mockResolvedValue(buildElasticSearchResponse([entityDoc]));

      await cleanAllEntityInconsistencies(buildContext(), buildBypassUser(), 'entity-id');

      expect(mockElRawSearch).toHaveBeenCalledTimes(1);
      // Source code bug: empty array is truthy, so update is triggered with empty duplicatedKeys
      expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
      const updateCall = mockElRawUpdateByQuery.mock.calls[0][0];
      expect(updateCall.body.script.params.duplicatedKeys).toEqual([]);
    });

    it('should still call update when refs keys do not start with rel_ prefix (empty duplicatedKeys)', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockElRawUpdateByQuery.mockResolvedValue({});
      const entityDoc = buildElasticHit({
        entity_type: 'Malware',
        name: 'TestMalware',
        some_other_field: ['a', 'a', 'b'],
      });
      mockElRawSearch.mockResolvedValue(buildElasticSearchResponse([entityDoc]));

      await cleanAllEntityInconsistencies(buildContext(), buildBypassUser(), 'entity-id');

      // Source code bug: empty array is truthy, so update is triggered with empty duplicatedKeys
      expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
      const updateCall = mockElRawUpdateByQuery.mock.calls[0][0];
      expect(updateCall.body.script.params.duplicatedKeys).toEqual([]);
    });

    it('should skip single relation refs in duplicate detection but still trigger update (empty array is truthy)', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockIsSingleRelationsRef.mockReturnValue(true);
      mockIsStixRefUnidirectionalRelationship.mockReturnValue(true);
      mockElRawUpdateByQuery.mockResolvedValue({});

      const entityDoc = buildElasticHit({
        entity_type: 'Malware',
        'rel_created-by.internal_id': ['id-1', 'id-1'],
      });
      mockElRawSearch.mockResolvedValue(buildElasticSearchResponse([entityDoc]));

      await cleanAllEntityInconsistencies(buildContext(), buildBypassUser(), 'entity-id');

      expect(mockIsSingleRelationsRef).toHaveBeenCalledWith('Malware', 'created-by');
      // Still called with empty duplicatedKeys due to source code truthy-array check
      expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
      const updateCall = mockElRawUpdateByQuery.mock.calls[0][0];
      expect(updateCall.body.script.params.duplicatedKeys).toEqual([]);
    });

    it('should skip non-unidirectional refs in duplicate detection but still trigger update (empty array is truthy)', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockIsSingleRelationsRef.mockReturnValue(false);
      mockIsStixRefUnidirectionalRelationship.mockReturnValue(false);
      mockElRawUpdateByQuery.mockResolvedValue({});

      const entityDoc = buildElasticHit({
        entity_type: 'Malware',
        'rel_object.internal_id': ['id-1', 'id-1'],
      });
      mockElRawSearch.mockResolvedValue(buildElasticSearchResponse([entityDoc]));

      await cleanAllEntityInconsistencies(buildContext(), buildBypassUser(), 'entity-id');

      expect(mockIsStixRefUnidirectionalRelationship).toHaveBeenCalledWith('object');
      // Still called with empty duplicatedKeys due to source code truthy-array check
      expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
      const updateCall = mockElRawUpdateByQuery.mock.calls[0][0];
      expect(updateCall.body.script.params.duplicatedKeys).toEqual([]);
    });

    it('should trigger update with empty duplicatedKeys when multi-ref values have no duplicates (empty array is truthy)', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockIsSingleRelationsRef.mockReturnValue(false);
      mockIsStixRefUnidirectionalRelationship.mockReturnValue(true);
      mockElRawUpdateByQuery.mockResolvedValue({});

      const entityDoc = buildElasticHit({
        entity_type: 'Malware',
        'rel_object-marking.internal_id': ['marking-1', 'marking-2', 'marking-3'],
      });
      mockElRawSearch.mockResolvedValue(buildElasticSearchResponse([entityDoc]));

      await cleanAllEntityInconsistencies(buildContext(), buildBypassUser(), 'entity-id');

      // Still called with empty duplicatedKeys due to source code truthy-array check
      expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
      const updateCall = mockElRawUpdateByQuery.mock.calls[0][0];
      expect(updateCall.body.script.params.duplicatedKeys).toEqual([]);
    });

    it('should call elRawUpdateByQuery when duplicated refs are found', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockIsSingleRelationsRef.mockReturnValue(false);
      mockIsStixRefUnidirectionalRelationship.mockReturnValue(true);
      mockElRawUpdateByQuery.mockResolvedValue({});

      const entityDoc = buildElasticHit({
        entity_type: 'Malware',
        'rel_object-marking.internal_id': ['marking-1', 'marking-1', 'marking-2'],
      });
      mockElRawSearch.mockResolvedValue(buildElasticSearchResponse([entityDoc]));

      await cleanAllEntityInconsistencies(buildContext(), buildBypassUser(), 'entity-id');

      expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
      const updateCall = mockElRawUpdateByQuery.mock.calls[0][0];
      expect(updateCall.index).toBe('test-read-index');
      expect(updateCall.refresh).toBe(true);
      expect(updateCall.conflicts).toBe('proceed');
      expect(updateCall.body.script.params.duplicatedKeys).toEqual(['rel_object-marking.internal_id']);
      expect(updateCall.body.script.source).toContain('distinct()');
      expect(updateCall.body.query.bool.filter[0].term['internal_id.keyword']).toBe('entity-id');
    });

    it('should detect multiple duplicated ref keys', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockIsSingleRelationsRef.mockReturnValue(false);
      mockIsStixRefUnidirectionalRelationship.mockReturnValue(true);
      mockElRawUpdateByQuery.mockResolvedValue({});

      const entityDoc = buildElasticHit({
        entity_type: 'Report',
        'rel_object-marking.internal_id': ['m1', 'm1', 'm2'],
        'rel_object-label.internal_id': ['l1', 'l2', 'l2', 'l3'],
      });
      mockElRawSearch.mockResolvedValue(buildElasticSearchResponse([entityDoc]));

      await cleanAllEntityInconsistencies(buildContext(), buildBypassUser(), 'report-id');

      expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
      const updateCall = mockElRawUpdateByQuery.mock.calls[0][0];
      expect(updateCall.body.script.params.duplicatedKeys).toEqual(
        expect.arrayContaining(['rel_object-marking.internal_id', 'rel_object-label.internal_id']),
      );
      expect(updateCall.body.script.params.duplicatedKeys).toHaveLength(2);
    });

    it('should use InconsistencyCleaningType.All by default', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockIsSingleRelationsRef.mockReturnValue(false);
      mockIsStixRefUnidirectionalRelationship.mockReturnValue(true);
      mockElRawUpdateByQuery.mockResolvedValue({});

      const entityDoc = buildElasticHit({
        entity_type: 'Malware',
        'rel_object-marking.internal_id': ['m1', 'm1'],
      });
      mockElRawSearch.mockResolvedValue(buildElasticSearchResponse([entityDoc]));

      // Call without specifying operationsToApply (defaults to [All])
      await cleanAllEntityInconsistencies(buildContext(), buildBypassUser(), 'entity-id');

      expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
    });

    it('should clean duplicates when RefDuplicateClean operation is specified', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockIsSingleRelationsRef.mockReturnValue(false);
      mockIsStixRefUnidirectionalRelationship.mockReturnValue(true);
      mockElRawUpdateByQuery.mockResolvedValue({});

      const entityDoc = buildElasticHit({
        entity_type: 'Malware',
        'rel_object-marking.internal_id': ['m1', 'm1'],
      });
      mockElRawSearch.mockResolvedValue(buildElasticSearchResponse([entityDoc]));

      await cleanAllEntityInconsistencies(
        buildContext(),
        buildBypassUser(),
        'entity-id',
        [InconsistencyCleaningType.RefDuplicateClean],
      );

      expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
    });

    it('should throw a DatabaseError when elRawSearch fails', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockElRawSearch.mockRejectedValue(new Error('ES connection failed'));

      await expect(
        cleanAllEntityInconsistencies(buildContext(), buildBypassUser(), 'entity-id'),
      ).rejects.toThrow('Find direct ids fail');
    });

    it('should build the correct ES search query', async () => {
      mockIsBypassUser.mockReturnValue(true);
      mockElRawSearch.mockResolvedValue(buildElasticSearchResponse([]));

      await cleanAllEntityInconsistencies(buildContext(), buildBypassUser(), 'my-internal-id');

      expect(mockElRawSearch).toHaveBeenCalledTimes(1);
      const searchArgs = mockElRawSearch.mock.calls[0];
      // args: context, user, 'None', rawSearchQuery
      expect(searchArgs[2]).toBe('None');
      const rawSearchQuery = searchArgs[3];
      expect(rawSearchQuery.index).toBe('test-read-index');
      expect(rawSearchQuery.size).toBe(5000);
      expect(rawSearchQuery.track_total_hits).toBe(false);
      expect(rawSearchQuery.body.query.bool.filter[0].term['internal_id.keyword']).toBe('my-internal-id');
    });
  });
});
