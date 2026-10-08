import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { curationResolve } from '../../../../src/modules/curation/curation-resolve';
import { internalFindByIds, pageEntitiesConnection, topEntitiesList } from '../../../../src/database/middleware-loader';
import { addCurationResolveCount } from '../../../../src/manager/telemetryManager';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../../src/schema/stixDomainObject';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  topEntitiesList: vi.fn(async () => []),
}));
vi.mock('../../../../src/manager/telemetryManager', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/manager/telemetryManager')>()),
  addCurationResolveCount: vi.fn(),
}));

const context = {} as AuthContext;
const analyst = { id: 'analyst-id' } as unknown as AuthUser;
const intrusionSet = (id: string, name: string, aliases: string[] = []) => ({
  internal_id: id,
  standard_id: `intrusion-set--${id}`,
  entity_type: ENTITY_TYPE_INTRUSION_SET,
  name,
  aliases,
});
const page = (...nodes: ReturnType<typeof intrusionSet>[]) => ({ edges: nodes.map((node) => ({ node })) });

describe('resolving an importer name', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('binds nothing when two entities share the name, without trying the fuzzy search', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue([
      intrusionSet('set-a', 'Shadow Lynx Group', ['Shadow Lynx']),
      intrusionSet('set-b', 'Lynx Collective', ['Shadow Lynx']),
    ] as never);
    vi.mocked(pageEntitiesConnection).mockResolvedValue(page(intrusionSet('set-a', 'Shadow Lynx Group', ['Shadow Lynx'])) as never);
    await expect(curationResolve(context, analyst, 'Shadow Lynx', ENTITY_TYPE_INTRUSION_SET)).resolves.toBeNull();
    expect(pageEntitiesConnection).not.toHaveBeenCalled();
    expect(addCurationResolveCount).toHaveBeenCalledWith(false);
  });

  it('binds the only entity with the exact name', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue([intrusionSet('set-a', 'Shadow Lynx')] as never);
    const resolution = await curationResolve(context, analyst, 'Shadow Lynx', ENTITY_TYPE_INTRUSION_SET);
    expect(resolution).toEqual(expect.objectContaining({ entity_id: 'set-a', match_type: 'exact', score: 1 }));
    expect(pageEntitiesConnection).not.toHaveBeenCalled();
    expect(addCurationResolveCount).toHaveBeenCalledWith(true);
  });

  it('falls back to the canonical forms when no entity has the exact name or alias', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue([] as never);
    vi.mocked(pageEntitiesConnection).mockResolvedValue(page(intrusionSet('set-a', 'Shadow-Lynx')) as never);
    const resolution = await curationResolve(context, analyst, 'Shadow Lynx', ENTITY_TYPE_INTRUSION_SET);
    expect(resolution).toEqual(expect.objectContaining({ entity_id: 'set-a', match_type: 'canonical' }));
    expect(addCurationResolveCount).toHaveBeenCalledWith(true);
  });

  it('binds an alias no identifier carries as an alias, looked up in the aliases of the requested type', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue([] as never);
    vi.mocked(topEntitiesList).mockResolvedValueOnce([intrusionSet('set-a', 'Graceful Spider', ['TA505'])] as never);
    const resolution = await curationResolve(context, analyst, 'ta505', ENTITY_TYPE_INTRUSION_SET);
    expect(resolution).toEqual(expect.objectContaining({ entity_id: 'set-a', match_type: 'alias', score: 0.98, matched_value: 'TA505' }));
    expect(topEntitiesList).toHaveBeenCalledWith(context, analyst, [ENTITY_TYPE_INTRUSION_SET], expect.objectContaining({
      filters: expect.objectContaining({ filters: [expect.objectContaining({ key: ['alias'], values: ['ta505'] })] }),
    }));
    expect(pageEntitiesConnection).not.toHaveBeenCalled();
  });

  it('binds nothing when two entities carry the name as an alias, whatever the fuzzy search would hold', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue([] as never);
    vi.mocked(topEntitiesList).mockResolvedValueOnce([
      intrusionSet('set-a', 'Graceful Spider', ['TA505']),
      intrusionSet('set-b', 'Evil Corp', ['TA505']),
    ] as never);
    vi.mocked(pageEntitiesConnection).mockResolvedValue(page(intrusionSet('set-a', 'Graceful Spider', ['TA505'])) as never);
    await expect(curationResolve(context, analyst, 'TA505', ENTITY_TYPE_INTRUSION_SET)).resolves.toBeNull();
    expect(pageEntitiesConnection).not.toHaveBeenCalled();
  });

  it('leaves an entity found only through its other STIX identifiers to the other match types', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue([intrusionSet('set-renamed', 'Amber Heron')] as never);
    vi.mocked(pageEntitiesConnection).mockResolvedValue(page(intrusionSet('set-a', 'Shadow-Lynx')) as never);
    const resolution = await curationResolve(context, analyst, 'Shadow Lynx', ENTITY_TYPE_INTRUSION_SET);
    expect(resolution).toEqual(expect.objectContaining({ entity_id: 'set-a', match_type: 'canonical', matched_value: 'Shadow-Lynx' }));
    expect(pageEntitiesConnection).toHaveBeenCalled();
  });
});
