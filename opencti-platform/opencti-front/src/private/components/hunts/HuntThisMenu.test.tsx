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

// Each query answers in turn: the derived content first, then the flagged threats when nothing was derived
const answer = (...answers: unknown[]) => {
  answers.forEach((data) => vi.mocked(fetchQuery).mockReturnValueOnce({ toPromise: () => Promise.resolve(data) } as never));
};
const queryText = (call: number) => (vi.mocked(fetchQuery).mock.calls[call][0] as unknown as { params: { text: string } }).params.text;

const pir = { id: 'pir-id', entity_type: 'Pir', name: 'Finance sector' };

const derivedFromPir = {
  entity: { id: 'pir-id', entity_type: 'Pir', name: 'Finance sector', relation: 'self' },
  suggested_type: 'indicators',
  sources: [
    { id: 'intrusion-set-1', entity_type: 'Intrusion-Set', name: 'Finance intrusion set', relation: 'flagged' },
    { id: 'malware-1', entity_type: 'Malware', name: 'Finance loader', relation: 'uses' },
  ],
  targets: [
    { id: 'intrusion-set-1', entity_type: 'Intrusion-Set', name: 'Finance intrusion set', relation: 'flagged' },
    { id: 'malware-1', entity_type: 'Malware', name: 'Finance loader', relation: 'uses' },
  ],
  elements: [{ id: 'indicator-1', entity_type: 'Indicator', name: '198.51.100.7', value_types: ['IPv4-Addr'], source_ids: ['intrusion-set-1'] }],
  elements_truncated: false,
  unsupported_count: 0,
  techniques: [],
  rules: [],
  rules_truncated: false,
};

describe('Hunt this from a PIR', () => {
  afterEach(() => {
    vi.mocked(fetchQuery).mockReset();
  });

  it('hunts the indicators of the threats the PIR flags, and targets those threats', async () => {
    answer({ huntDerivedContent: derivedFromPir });
    const prefill = await fetchHuntPrefill(pir);
    expect(queryText(0)).toContain('huntDerivedContent');
    expect(vi.mocked(fetchQuery).mock.calls[0][1]).toEqual({ entityId: 'pir-id' });
    expect(prefill.derived).toEqual(derivedFromPir);
    expect(prefill.values).toMatchObject({ name: 'Hunt - Finance sector', hunt_type: 'indicators' });
    expect(prefill.values.iocEntities?.map((option) => option.value)).toEqual(['intrusion-set-1', 'malware-1']);
    expect(prefill.values.huntTargets?.map((option) => option.value)).toEqual(['intrusion-set-1', 'malware-1']);
  });

  it('prefills the flagged threats with the highest PIR score when nothing can be derived, and counts the others', async () => {
    answer({ huntDerivedContent: null }, flaggedThreats(100, 240));
    const prefill = await fetchHuntPrefill(pir);
    expect(queryText(1)).toContain('orderBy: pir_score');
    expect(queryText(1)).toContain('orderMode: desc');
    expect(vi.mocked(fetchQuery).mock.calls[1][1]).toMatchObject({ pirId: 'pir-id', first: 100 });
    expect(prefill.values.huntTargets).toHaveLength(100);
    expect(prefill.values.huntTargets?.[0]).toMatchObject({ value: 'intrusion-set-0', label: 'Intrusion set 0' });
    expect(prefill.pirTargets).toEqual({ flagged: 240, selected: 100 });
    expect(prefill.derived).toBeNull();
  });

  it('prefills every flagged threat when the PIR flags fewer than the limit', async () => {
    answer({ huntDerivedContent: null }, flaggedThreats(3, 3));
    const prefill = await fetchHuntPrefill(pir);
    expect(prefill.values.huntTargets).toHaveLength(3);
    expect(prefill.pirTargets).toEqual({ flagged: 3, selected: 3 });
  });
});
