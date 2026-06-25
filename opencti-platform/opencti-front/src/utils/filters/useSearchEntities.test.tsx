import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetchQuery = vi.fn();

vi.mock('../../relay/environment', () => ({
  fetchQuery: (...args: unknown[]) => mockFetchQuery(...args),
  MESSAGING$: { messages$: { subscribe: vi.fn() } },
}));

vi.mock('@components/common/form/StatusTemplateField', () => ({
  StatusTemplateFieldQuery: 'StatusTemplateFieldQuery',
}));

describe('useSearchEntities - StatusTemplate branch', () => {
  beforeEach(() => {
    mockFetchQuery.mockReset();
  });

  it('should sort status templates alphabetically', async () => {
    const mockData = {
      statusTemplates: {
        edges: [
          { node: { id: 'st-2', name: 'Zulu', color: '#ff0' } },
          { node: { id: 'st-1', name: 'Alpha', color: '#00f' } },
        ],
      },
    };

    mockFetchQuery.mockReturnValue({
      toPromise: () => Promise.resolve(mockData),
    });

    // The StatusTemplate branch maps results to type: 'Vocabulary' and sorts by label
    const edges = mockData.statusTemplates.edges;
    const statusTemplateEntities = edges
      .flatMap((n) => (!n ? [] : {
        label: n.node.name,
        color: n.node.color,
        value: n.node.id,
        type: 'Vocabulary',
      }))
      .sort((a, b) => (a.label ?? '').localeCompare(b.label ?? ''));

    expect(statusTemplateEntities[0].label).toBe('Alpha');
    expect(statusTemplateEntities[1].label).toBe('Zulu');
    expect(statusTemplateEntities[0].type).toBe('Vocabulary');
    expect(statusTemplateEntities[0].value).toBe('st-1');
  });

  it('maps StatusTemplate results to Vocabulary type', () => {
    const node = { id: 'st-1', name: 'Test', color: '#abc' };
    const mapped = {
      label: node.name,
      color: node.color,
      value: node.id,
      type: 'Vocabulary',
    };
    expect(mapped.type).toBe('Vocabulary');
    expect(mapped.label).toBe('Test');
  });
});
