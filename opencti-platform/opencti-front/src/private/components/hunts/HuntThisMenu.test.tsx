import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchQuery } from '../../../relay/environment';
import { fetchHuntPrefill } from './HuntThisMenu';

vi.mock('../../../relay/environment', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../relay/environment')>();
  return { ...original, fetchQuery: vi.fn() };
});

const flaggedThreats = (count: number, globalCount: number) => ({
  stixDomainObjects: {
    pageInfo: { globalCount },
    edges: Array.from({ length: count }, (_, index) => ({
      node: { id: `intrusion-set-${index}`, entity_type: 'Intrusion-Set', representative: { main: `Intrusion set ${index}` } },
    })),
  },
});

const answer = (data: unknown) => vi.mocked(fetchQuery).mockReturnValue({ toPromise: () => Promise.resolve(data) } as never);

const pir = { id: 'pir-id', entity_type: 'Pir', name: 'Finance sector' };

describe('Hunt this from a PIR', () => {
  afterEach(() => {
    vi.mocked(fetchQuery).mockReset();
  });

  it('prefills the flagged threats with the highest PIR score and counts the others', async () => {
    answer(flaggedThreats(100, 240));
    const prefill = await fetchHuntPrefill(pir);
    const [query, variables] = vi.mocked(fetchQuery).mock.calls[0];
    expect((query as unknown as { params: { text: string } }).params.text).toContain('orderBy: pir_score');
    expect((query as unknown as { params: { text: string } }).params.text).toContain('orderMode: desc');
    expect(variables).toMatchObject({ pirId: 'pir-id', first: 100 });
    expect(prefill.values.huntTargets).toHaveLength(100);
    expect(prefill.values.huntTargets?.[0]).toMatchObject({ value: 'intrusion-set-0', label: 'Intrusion set 0' });
    expect(prefill.pirTargets).toEqual({ flagged: 240, selected: 100 });
    expect(prefill.derived).toBeNull();
  });

  it('prefills every flagged threat when the PIR flags fewer than the limit', async () => {
    answer(flaggedThreats(3, 3));
    const prefill = await fetchHuntPrefill(pir);
    expect(prefill.values.huntTargets).toHaveLength(3);
    expect(prefill.pirTargets).toEqual({ flagged: 3, selected: 3 });
  });
});
