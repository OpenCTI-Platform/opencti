import { beforeEach, describe, expect, it, vi } from 'vitest';
import { pageRegardingEntitiesConnection, storeLoadById, topEntitiesList, topRelationsList } from '../../../../src/database/middleware-loader';
import { deriveHuntContent } from '../../../../src/modules/hunt/hunt-derivation';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { ENTITY_TYPE_PIR } from '../../../../src/modules/pir/pir-types';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  storeLoadById: vi.fn(),
  pageRegardingEntitiesConnection: vi.fn(),
  topEntitiesList: vi.fn(),
  topRelationsList: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

const pir = { internal_id: 'pir-1', standard_id: 'pir--1', entity_type: ENTITY_TYPE_PIR, name: 'Finance sector' };
const intrusionSet = { internal_id: 'intrusion-set-1', standard_id: 'intrusion-set--1', entity_type: 'Intrusion-Set', name: 'Finance intrusion set' };
const malware = { internal_id: 'malware-1', standard_id: 'malware--1', entity_type: 'Malware', name: 'Finance loader' };
const indicator = { internal_id: 'indicator-1', standard_id: 'indicator--1', entity_type: 'Indicator', name: 'Finance C2', pattern_type: 'stix', pattern: "[ipv4-addr:value = '198.51.100.7']" };
const elements = [intrusionSet, malware, indicator];

describe('Hunt derived from a PIR', () => {
  beforeEach(() => {
    // The PIR is no STIX core object: only its own type loads it
    vi.mocked(storeLoadById).mockImplementation(async (_context, _user, id, type) => (id === pir.internal_id && type === ENTITY_TYPE_PIR ? pir : undefined) as never);
    vi.mocked(topEntitiesList).mockImplementation(async (_context, _user, _types, args) => ((args as { pirId?: string }).pirId === pir.internal_id ? [intrusionSet] : []) as never);
    vi.mocked(findByIds).mockImplementation(async (_context, _user, ids) => elements.filter((element) => (ids as string[]).includes(element.internal_id)) as never);
    vi.mocked(pageRegardingEntitiesConnection).mockImplementation(async (_context, _user, id, relationType, types) => ({
      edges: id === intrusionSet.internal_id && relationType === 'uses' && (types as string[]).includes('Malware') ? [{ node: malware }] : [],
    }) as never);
    vi.mocked(topRelationsList).mockImplementation(async (_context, _user, relationType, args) => {
      const { toId } = args as { toId?: string };
      return (relationType === 'indicates' && toId === intrusionSet.internal_id ? [{ fromId: indicator.internal_id, toId }] : []) as never;
    });
  });

  it('should follow the threats the PIR flags: their indicators, the malware they use, the threats as targets', async () => {
    const derived = await deriveHuntContent(testContext, ADMIN_USER, pir.internal_id);
    expect(derived?.entity).toEqual({ id: pir.internal_id, entity_type: ENTITY_TYPE_PIR, name: 'Finance sector', relation: 'self' });
    // The score is read on the flagged threats for this PIR, the most relevant first
    expect(topEntitiesList).toHaveBeenCalledWith(testContext, ADMIN_USER, expect.arrayContaining(['Intrusion-Set', 'Malware']), expect.objectContaining({ pirId: pir.internal_id, orderBy: 'pir_score', orderMode: 'desc' }));
    expect(derived?.suggested_type).toEqual('indicators');
    expect(derived?.sources).toEqual(expect.arrayContaining([
      { id: intrusionSet.internal_id, entity_type: 'Intrusion-Set', name: 'Finance intrusion set', relation: 'flagged' },
      { id: malware.internal_id, entity_type: 'Malware', name: 'Finance loader', relation: 'uses' },
    ]));
    expect(derived?.targets.map((target) => target.id).sort()).toEqual([intrusionSet.internal_id, malware.internal_id].sort());
    expect(derived?.elements).toEqual([expect.objectContaining({ id: indicator.internal_id, value_types: ['IPv4-Addr'], source_ids: [intrusionSet.internal_id] })]);
  });

  it('should derive nothing from a PIR that flags no threat', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([] as never);
    const derived = await deriveHuntContent(testContext, ADMIN_USER, pir.internal_id);
    expect(derived).toMatchObject({ suggested_type: null, sources: [], targets: [], elements: [], rules: [] });
  });
});
