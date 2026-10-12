import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { isEnterpriseEdition } from '../../../../src/enterprise-edition/ee';
import { restrictSourceQueryToEdition } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-domain';
import { sourceScorecardsNumber, sourceScorecardsScatter } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-widgets';
import sourceIntelligenceResolvers from '../../../../src/modules/sourceIntelligence/sourceIntelligence-resolvers';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>();
  return { ...actual, isEnterpriseEdition: vi.fn() };
});

const context = { user: { id: 'user-1' } } as unknown as AuthContext;
const user = context.user as AuthUser;
const relevanceFilter = { key: ['latest_relevance'], values: ['0.5'], operator: 'gt', mode: 'or' };
const nested = (filter: unknown) => ({ mode: 'and', filters: [], filterGroups: [{ mode: 'and', filters: [filter], filterGroups: [] }] }) as any;

// Field resolvers are plain functions here: the GraphQL info argument is not used
const resolve = (type: 'Source' | 'SourceScorecard', field: string, parent: Record<string, unknown>) => {
  const resolvers = sourceIntelligenceResolvers as any;
  return resolvers[type][field](parent, {}, context, {});
};

describe('Source intelligence Enterprise Edition metrics after a license downgrade', () => {
  beforeEach(() => {
    vi.mocked(isEnterpriseEdition).mockResolvedValue(false);
  });

  it('should not serve the relevance stored by an Enterprise Edition computation', async () => {
    expect(await resolve('Source', 'latest_relevance', { latest_relevance: 0.8 })).toBeNull();
    expect(await resolve('SourceScorecard', 'relevance', { relevance: 0.8 })).toBeNull();
    expect(await resolve('SourceScorecard', 'pir_matched_count', { pir_matched_count: 12 })).toBeNull();
  });

  it('should serve the relevance in Enterprise Edition', async () => {
    vi.mocked(isEnterpriseEdition).mockResolvedValue(true);
    expect(await resolve('Source', 'latest_relevance', { latest_relevance: 0.8 })).toBe(0.8);
    expect(await resolve('SourceScorecard', 'relevance', { relevance: 0.8 })).toBe(0.8);
    expect(await resolve('SourceScorecard', 'pir_matched_count', { pir_matched_count: 12 })).toBe(12);
  });

  it('should neither filter nor sort sources on their relevance outside Enterprise Edition', async () => {
    await expect(restrictSourceQueryToEdition(context, { filters: nested(relevanceFilter) })).rejects.toThrow('requires an Enterprise Edition license');
    expect(await restrictSourceQueryToEdition(context, { orderBy: 'latest_relevance' })).toEqual({ orderBy: null });
    const kept = { orderBy: 'latest_accuracy', filters: nested({ ...relevanceFilter, key: ['latest_accuracy'] }) };
    expect(await restrictSourceQueryToEdition(context, kept)).toBe(kept);
    vi.mocked(isEnterpriseEdition).mockResolvedValue(true);
    const enterprise = { orderBy: 'latest_relevance', filters: nested(relevanceFilter) };
    expect(await restrictSourceQueryToEdition(context, enterprise)).toBe(enterprise);
  });

  it('should refuse the Enterprise Edition metrics of the widgets outside Enterprise Edition', async () => {
    await expect(sourceScorecardsNumber(context, user, { metric: 'relevance' })).rejects.toThrow('requires an Enterprise Edition license');
    await expect(sourceScorecardsScatter(context, user, { xMetric: 'accuracy', yMetric: 'noise', sizeMetric: 'relevance' })).rejects.toThrow('requires an Enterprise Edition license');
  });
});
