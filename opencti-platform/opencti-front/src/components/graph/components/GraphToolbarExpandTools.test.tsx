import React from 'react';
import { act } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import { graphNode } from '../../../utils/tests/graphTestData';
import GraphToolbarExpandTools, { expandRelationshipsQuery } from './GraphToolbarExpandTools';

const mocks = vi.hoisted(() => ({
  dialogContent: vi.fn(),
  fetchQuery: vi.fn(),
  resetFilters: vi.fn(),
  onInvestigationExpand: vi.fn(),
}));

vi.mock('@filigran/design-system', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@filigran/design-system')>()),
  Dialog: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  DialogContent: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  DialogTitle: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock('@components/workspaces/investigations/InvestigationExpandDialogContent', () => ({
  default: (props: Record<string, unknown>) => {
    mocks.dialogContent(props);
    return null;
  },
}));

vi.mock('@components/workspaces/investigations/utils/useInvestigationState', () => ({
  useInvestigationState: () => ({ containsExpandOp: () => false }),
}));

vi.mock('@components/workspaces/investigations/dialog/InvestigationRollBackExpandDialog', () => ({ default: () => null }));

vi.mock('../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../relay/environment')>()),
  fetchQuery: mocks.fetchQuery,
}));

vi.mock('../GraphContext', () => ({
  useGraphContext: () => ({
    graphData: { nodes: [], links: [] },
    rawObjects: [],
    graphState: { selectedNodes: [graphNode({ id: 'malware' })], selectedLinks: [], isExpandOpen: true },
  }),
}));

vi.mock('../utils/useGraphInteractions', () => ({
  default: () => ({ setLinearProgress: vi.fn(), setIsExpandOpen: vi.fn(), resetFilters: mocks.resetFilters }),
}));

const relationships = { stixRelationships: { edges: [{ node: { id: 'uses', from: { id: 'malware' }, to: { id: 'actor' } } }] } };

const submitExpand = async (resetFilters: boolean) => {
  const { calls } = mocks.dialogContent.mock;
  const { onSubmit } = calls[calls.length - 1][0];
  await act(() => onSubmit(
    {
      entity_types: [{ label: 'Intrusion-Set', value: 'Intrusion-Set' }],
      relationship_types: [],
      reset_filters: resetFilters,
    },
    { resetForm: vi.fn() },
  ));
};

const renderExpand = () => testRender(<GraphToolbarExpandTools onInvestigationExpand={mocks.onInvestigationExpand} />);

describe('GraphToolbarExpandTools', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.fetchQuery.mockReturnValue({ toPromise: () => Promise.resolve(relationships) });
  });

  it('resets the graph filters after the expand when Reset filters is on', async () => {
    renderExpand();

    await submitExpand(true);

    expect(mocks.onInvestigationExpand).toHaveBeenCalledWith([relationships.stixRelationships.edges[0].node, { id: 'actor' }]);
    expect(mocks.resetFilters).toHaveBeenCalledTimes(1);
    expect(mocks.resetFilters.mock.invocationCallOrder[0]).toBeGreaterThan(mocks.onInvestigationExpand.mock.invocationCallOrder[0]);
  });

  it('keeps the graph filters when Reset filters is off', async () => {
    renderExpand();

    await submitExpand(false);

    expect(mocks.onInvestigationExpand).toHaveBeenCalled();
    expect(mocks.resetFilters).not.toHaveBeenCalled();
  });

  describe('the expand query', () => {
    interface Selection {
      kind: string;
      name?: string;
      type?: string;
      selections?: readonly Selection[];
    }

    const linkedField = (selections: readonly Selection[] | undefined, name: string) => {
      return (selections ?? []).find((s) => s.kind === 'LinkedField' && s.name === name);
    };

    // The fields selected on an endpoint whatever its type: the ones of fragments on a single type are left out.
    const fieldsOfEveryType = (selections: readonly Selection[] | undefined): Selection[] => {
      return (selections ?? []).flatMap((s) => {
        if (s.kind !== 'InlineFragment') return [s];
        return ['StixObject', 'BasicObject'].includes(s.type ?? '') ? fieldsOfEveryType(s.selections) : [];
      });
    };

    const endpoint = (side: 'from' | 'to') => {
      const { operation } = expandRelationshipsQuery as unknown as { operation: Selection };
      const node = ['stixRelationships', 'edges', 'node'].reduce<Selection | undefined>(
        (parent, name) => linkedField(parent?.selections, name),
        operation,
      );
      return linkedField(node?.selections, side);
    };

    // An endpoint without its representative is drawn "Unknown", as the narratives reached
    // through the `to` side of a relationship were (#16992).
    it.each(['from', 'to'] as const)('fetches the representative of the %s endpoint whatever its type', (side) => {
      const representative = linkedField(fieldsOfEveryType(endpoint(side)?.selections), 'representative');

      expect(representative?.selections?.map((s) => s.name)).toContain('main');
    });
  });
});
