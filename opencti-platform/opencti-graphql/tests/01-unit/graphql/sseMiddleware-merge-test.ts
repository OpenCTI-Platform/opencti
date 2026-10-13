import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return {
    ...actual,
    logApp: { info: vi.fn(), error: vi.fn(), debug: vi.fn(), warn: vi.fn() },
  };
});
vi.mock('../../../src/database/redis');
vi.mock('../../../src/database/stream/stream-handler', () => ({ createStreamProcessor: vi.fn() }));
vi.mock('../../../src/database/engine', () => ({ elCount: vi.fn(), elList: vi.fn(), elFindByIds: vi.fn() }));
vi.mock('../../../src/database/middleware-loader', () => ({ fullRelationsList: vi.fn() }));
vi.mock('../../../src/database/middleware', () => ({ stixLoadById: vi.fn(), storeLoadByIdsWithRefs: vi.fn() }));
vi.mock('../../../src/utils/access', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/utils/access')>();
  return { ...actual, isUserCanAccessStixElement: vi.fn() };
});

import { isUserCanAccessStixElement } from '../../../src/utils/access';
// eslint-disable-next-line import/extensions
import { filterMergeEventSources } from '../../../src/graphql/sseMiddleware.js';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

const buildReport = (id: string, name: string) => ({
  id: `report--${id}`,
  type: 'report',
  spec_version: '2.1',
  name,
  extensions: { [STIX_EXT_OCTI]: { id, type: 'Report' } },
});

const buildMergeEventData = (sources: any[]) => ({
  version: '4',
  type: 'merge',
  scope: 'external',
  message: 'merges Report `Source A, Source B` in `Target`',
  data: buildReport('target', 'Target'),
  context: { patch: [], reverse_patch: [], sources },
});

const context = {} as any;
const user = { id: 'user-id' } as any;

describe('filterMergeEventSources', () => {
  beforeEach(() => {
    vi.mocked(isUserCanAccessStixElement).mockReset();
  });

  it('should return the event unchanged when all sources are accessible', async () => {
    vi.mocked(isUserCanAccessStixElement).mockResolvedValue(true);
    const eventData = buildMergeEventData([buildReport('a', 'Source A'), buildReport('b', 'Source B')]);
    const result = await filterMergeEventSources(context, user, eventData);
    expect(result).toBe(eventData);
    expect(isUserCanAccessStixElement).toHaveBeenCalledTimes(2);
  });

  it('should keep only accessible sources and rebuild the message', async () => {
    const sourceA = buildReport('a', 'Source A');
    const sourceB = buildReport('b', 'Source B');
    vi.mocked(isUserCanAccessStixElement).mockImplementation(async (_ctx, _user, instance: any) => instance === sourceA);
    const eventData = buildMergeEventData([sourceA, sourceB]);
    const result = await filterMergeEventSources(context, user, eventData);
    expect(result.context.sources).toEqual([sourceA]);
    expect(result.message).toEqual('merges Report `Source A` in `Target`');
    expect(result.data).toBe(eventData.data);
    expect(result.context.patch).toBe(eventData.context.patch);
    // Original event is not mutated
    expect(eventData.context.sources).toHaveLength(2);
    expect(eventData.message).toEqual('merges Report `Source A, Source B` in `Target`');
  });

  it('should remove all sources when none is accessible', async () => {
    vi.mocked(isUserCanAccessStixElement).mockResolvedValue(false);
    const eventData = buildMergeEventData([buildReport('a', 'Source A'), buildReport('b', 'Source B')]);
    const result = await filterMergeEventSources(context, user, eventData);
    expect(result.context.sources).toEqual([]);
    expect(result.message).toEqual('merges Report `` in `Target`');
  });

  it('should return the event unchanged when there is no source', async () => {
    const eventData = { ...buildMergeEventData([]), context: undefined };
    const result = await filterMergeEventSources(context, user, eventData);
    expect(result).toBe(eventData);
    expect(isUserCanAccessStixElement).not.toHaveBeenCalled();
  });
});
