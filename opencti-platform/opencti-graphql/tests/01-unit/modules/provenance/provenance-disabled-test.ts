import { describe, expect, it, vi } from 'vitest';
import { elRawGet, elUpdate } from '../../../../src/database/engine';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../../src/database/cache';
import { withProvenanceStixExtension } from '../../../../src/modules/provenance/provenance-stix';
import { computeCreationProvenance, isProvenanceRecordable, recordUpsertProvenance } from '../../../../src/modules/provenance/provenance-write';
import { creationProceduresBuilder, mergeProvenanceOnEntitiesMerge, prepareUpsertProvenance } from '../../../../src/modules/provenance/provenance-upsert';
import { STIX_EXT_OCTI_PROVENANCE } from '../../../../src/types/stix-2-1-extensions';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/modules/provenance/provenance-config', () => ({
  PROVENANCE_ENABLED: false,
  PROVENANCE_REASSERTION_WINDOW_MS: 24 * 60 * 60 * 1000,
  PROVENANCE_DEFAULT_TRACKED_TYPES: ['*'],
}));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/engine')>(),
  elUpdate: vi.fn(),
  elRawGet: vi.fn(),
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntitiesListFromCache: vi.fn(),
  getEntityFromCache: vi.fn(),
}));

const context = { source: 'provenance-disabled-test' } as AuthContext;
const user = { id: 'c0000000-0000-4000-8000-000000000003', name: 'Jane Analyst' } as AuthUser;
const element = { _index: 'opencti_stix_domain_objects-000001', internal_id: 'e0000000-0000-4000-8000-000000000001', entity_type: 'Malware' };
const assertion = {
  source_id: 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c001',
  source_kind: 'connector' as const,
  source_name: 'AlienVault',
  first_asserted_at: '2026-01-01T00:00:00.000Z',
  last_asserted_at: '2026-09-01T00:00:00.000Z',
  assert_count: 3,
  confidence: 50,
  work_id: null,
};

describe('Provenance disabled', () => {
  it('should never write nor read anything for a creation, an upsert or a merge', async () => {
    expect(await isProvenanceRecordable(context, user, 'Malware')).toEqual(false);
    expect(await computeCreationProvenance(context, user, 'Malware', { name: 'Emotet', confidence: 50 })).toBeNull();
    expect(await recordUpsertProvenance(context, user, element, { input: {}, confidence: 50 })).toBeNull();
    const inputs = [{ key: 'description', value: ['incoming'] }];
    const prepared = await prepareUpsertProvenance(context, user, { ...element, description: 'current' }, 'Malware', {
      basePatch: {},
      updatePatch: { description: 'incoming' },
      inputs,
      isConfidenceMatch: true,
      confidence: 50,
    });
    expect(prepared).toEqual({ inputs, record: null });
    await mergeProvenanceOnEntitiesMerge(context, user, element, [{ ...element, internal_id: 'e0000000-0000-4000-8000-000000000002', x_opencti_assertions: [assertion] }]);
    expect(elUpdate).not.toHaveBeenCalled();
    expect(elRawGet).not.toHaveBeenCalled();
    expect(getEntitiesListFromCache).not.toHaveBeenCalled();
  });

  it('should not preserve procedures on uses relationships', async () => {
    const builder = await creationProceduresBuilder(context, 'uses', { description: 'Spearphishing with macros', to: { entity_type: 'Attack-Pattern' } });
    expect(builder).toBeUndefined();
    expect(getEntityFromCache).not.toHaveBeenCalled();
  });

  it('should not add the provenance extension to STIX objects', () => {
    const stix = { id: 'malware--0d5ba8f1-1e8f-5a4a-8b5c-1d1f2a3b4c5d', type: 'malware', extensions: {} };
    const converted = withProvenanceStixExtension({ entity_type: 'Malware', x_opencti_assertions: [assertion] }, stix);
    expect(converted).toBe(stix);
    expect(converted.extensions).not.toHaveProperty(STIX_EXT_OCTI_PROVENANCE);
  });
});
