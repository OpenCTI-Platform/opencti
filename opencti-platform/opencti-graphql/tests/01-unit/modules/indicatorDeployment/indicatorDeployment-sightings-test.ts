import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { generatedPairSightingOf, withoutWindowMatchedGeneratedSightings } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-sightings';
import { hitsSightingStixId, validationResultSightingStixId } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-utils';
import { ENTITY_TYPE_INDICATOR } from '../../../../src/modules/indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../../src/modules/securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../../src/schema/stixDomainObject';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
}));

const context = {} as AuthContext;
const INDICATOR_ID = 'a6d6f6a4-6a87-4c39-9d4f-7d2f3e6c1a01';
const PLATFORM_ID = 'b3c1e0d2-5f44-4b1e-8a3c-2e9d7f6a4b02';
const REQUEST_ID = 'c8e2f1a3-7b55-4c2f-9b4d-3f0e8a7b5c03';
const pairInput = {
  from: { entity_type: ENTITY_TYPE_INDICATOR, internal_id: INDICATOR_ID },
  to: { entity_type: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, internal_id: PLATFORM_ID },
};
const hits = { internal_id: 'hits', standard_id: 'sighting--0f1e2d3c-4b5a-4968-8778-695a4b3c2d1e', x_opencti_stix_ids: [hitsSightingStixId(INDICATOR_ID, PLATFORM_ID)] };
const result = {
  internal_id: 'result',
  standard_id: 'sighting--1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d',
  x_opencti_stix_ids: [validationResultSightingStixId(REQUEST_ID, INDICATOR_ID, PLATFORM_ID)],
};
const ordinary = { internal_id: 'ordinary', standard_id: 'sighting--2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e', x_opencti_stix_ids: [] };

describe('existing sightings an ordinary sighting creation upserts', () => {
  beforeEach(() => {
    // One validation request includes the pair
    vi.mocked(fullEntitiesList).mockReset();
    vi.mocked(fullEntitiesList).mockImplementation((async (...args: unknown[]) => {
      const opts = args[3] as { callback: (requests: Array<{ internal_id: string }>) => Promise<boolean> };
      await opts.callback([{ internal_id: REQUEST_ID }]);
      return [];
    }) as never);
  });

  it('keeps every sighting of an input that is not an indicator and security platform pair', async () => {
    const reportInput = { ...pairInput, from: { entity_type: ENTITY_TYPE_CONTAINER_REPORT, internal_id: INDICATOR_ID } };
    const sightings = [hits, result, ordinary];
    expect(await withoutWindowMatchedGeneratedSightings(context, reportInput, ['sighting--new'], sightings)).toEqual(sightings);
    expect(fullEntitiesList).not.toHaveBeenCalled();
  });

  it('leaves out the hits and validation result sightings of the pair found by their time window only', async () => {
    const kept = await withoutWindowMatchedGeneratedSightings(context, pairInput, ['sighting--new'], [hits, result, ordinary]);
    expect(kept).toEqual([ordinary]);
  });

  it('reads the validation requests of the pair once, whatever the number of candidates', async () => {
    const other = { ...ordinary, internal_id: 'other', standard_id: 'sighting--3c4d5e6f-7a8b-4c9d-8e0f-2a3b4c5d6e7f' };
    expect(await withoutWindowMatchedGeneratedSightings(context, pairInput, ['sighting--new'], [ordinary, result, other])).toEqual([ordinary, other]);
    expect(fullEntitiesList).toHaveBeenCalledTimes(1);
    // The hits sighting is told by its id alone
    vi.mocked(fullEntitiesList).mockClear();
    expect(await withoutWindowMatchedGeneratedSightings(context, pairInput, ['sighting--new'], [hits])).toEqual([]);
    expect(fullEntitiesList).not.toHaveBeenCalled();
  });

  it('names the validation request a result sighting belongs to', async () => {
    expect(await generatedPairSightingOf(context, pairInput, result.x_opencti_stix_ids)).toEqual({ kind: 'validation_result', requestId: REQUEST_ID });
    expect(await generatedPairSightingOf(context, pairInput, hits.x_opencti_stix_ids)).toEqual({ kind: 'hits' });
    expect(await generatedPairSightingOf(context, pairInput, [ordinary.standard_id])).toBeUndefined();
  });

  it('keeps a generated sighting the input reaches by one of its ids', async () => {
    expect(await withoutWindowMatchedGeneratedSightings(context, pairInput, [hits.standard_id], [hits, result, ordinary])).toEqual([hits, ordinary]);
    expect(await withoutWindowMatchedGeneratedSightings(context, pairInput, [result.internal_id], [hits, result, ordinary])).toEqual([result, ordinary]);
  });
});
