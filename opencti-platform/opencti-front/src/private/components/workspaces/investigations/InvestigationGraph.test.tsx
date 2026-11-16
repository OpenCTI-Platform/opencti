import React, { Suspense } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { useLazyLoadQuery } from 'react-relay';
import { createMockEnvironment, MockPayloadGenerator } from 'relay-test-utils';
import type { OperationDescriptor } from 'relay-runtime';
import { describe, expect, it, vi } from 'vitest';
import { ProvidersWrapper } from '../../../../utils/tests/test-render';
import InvestigationGraph, { investigationGraphQuery } from './InvestigationGraph';
import { InvestigationGraphQuery } from './__generated__/InvestigationGraphQuery.graphql';

const savedPositions = vi.hoisted(() => vi.fn());

// The canvas, the toolbar and the header are tested on their own: the graph stands in to show what the investigation gives it.
vi.mock('../../../../components/graph/Graph', async () => {
  const { useGraphContext } = await import('../../../../components/graph/GraphContext');
  return {
    default: ({ onPositionsChanged }: { onPositionsChanged?: (positions: object) => void }) => {
      const { editDisabledReason } = useGraphContext();
      return (
        <>
          <span>{editDisabledReason ?? 'editable'}</span>
          <button type="button" onClick={() => onPositionsChanged?.({ malware: { id: 'malware', x: 1, y: 2 } })}>Move an entity</button>
        </>
      );
    },
  };
});
vi.mock('./useInvestigationGraphEdit', () => ({ default: () => [savedPositions] }));
vi.mock('../../../../components/graph/GraphToolbar', () => ({ default: () => null }));
vi.mock('@components/workspaces/workspaceHeader/WorkspaceHeader', () => ({ default: () => null }));
vi.mock('@components/workspaces/investigations/utils/fetchMetaObjectsCount', () => ({ default: async (objects: unknown[]) => objects }));
// The objects of the investigation load page by page through their own query: an empty investigation is enough here.
vi.mock('../../../../utils/hooks/useQueryLoading', () => ({ default: () => ({}) }));
vi.mock('../../../../utils/hooks/usePreloadedPaginationFragment', () => ({
  default: () => ({
    data: { workspace: { objects: { edges: [], pageInfo: { globalCount: 0 } } } },
    hasMore: () => false,
    loadMore: () => {},
    isLoadingMore: () => false,
  }),
}));

const InvestigationGraphOf = () => {
  const { workspace } = useLazyLoadQuery<InvestigationGraphQuery>(investigationGraphQuery, { id: 'investigation-1' });
  return workspace ? <InvestigationGraph id="investigation-1" data={workspace} /> : null;
};

const renderGraph = (currentUserAccessRight: string) => {
  const relayEnv = createMockEnvironment();
  const resolve = (operation: OperationDescriptor) => MockPayloadGenerator.generate(operation, {
    Workspace: () => ({ id: 'investigation-1', currentUserAccessRight, graph_data: null }),
  });
  relayEnv.mock.queueOperationResolver(resolve);
  render(
    <ProvidersWrapper relayEnv={relayEnv}>
      <Suspense fallback="loading">
        <InvestigationGraphOf />
      </Suspense>
    </ProvidersWrapper>,
  );
};

describe('InvestigationGraph', () => {
  it('tells the graph that a view only member cannot change the investigation, and keeps the moves of the entities in the view', async () => {
    savedPositions.mockClear();
    renderGraph('view');
    expect(await screen.findByText('You have view access to this investigation')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Move an entity' }));
    expect(savedPositions).not.toHaveBeenCalled();
  });

  it('leaves the graph editable for an editor, and saves the moves of the entities', async () => {
    savedPositions.mockClear();
    renderGraph('edit');
    expect(await screen.findByText('editable')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Move an entity' }));
    expect(savedPositions).toHaveBeenCalledWith(expect.objectContaining({ variables: expect.objectContaining({ id: 'investigation-1' }) }));
  });
});
