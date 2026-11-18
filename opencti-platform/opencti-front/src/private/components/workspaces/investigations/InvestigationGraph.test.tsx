import React, { Suspense } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { useLazyLoadQuery } from 'react-relay';
import { createMockEnvironment, MockPayloadGenerator } from 'relay-test-utils';
import type { OperationDescriptor } from 'relay-runtime';
import { describe, expect, it, vi } from 'vitest';
import { createMockUserContext, ProvidersWrapper } from '../../../../utils/tests/test-render';
import InvestigationGraph, { investigationGraphQuery } from './InvestigationGraph';
import { InvestigationGraphQuery } from './__generated__/InvestigationGraphQuery.graphql';

const savedPositions = vi.hoisted(() => vi.fn());

// The canvas, the toolbar and the header are tested on their own: the graph stands in to show what the investigation gives it.
vi.mock('../../../../components/graph/Graph', async () => {
  const { useGraphContext } = await import('../../../../components/graph/GraphContext');
  return {
    default: ({ onPositionsChanged }: { onPositionsChanged?: (positions: object) => void }) => {
      const { readOnly } = useGraphContext();
      return (
        <>
          <span>{readOnly ? 'read only' : 'editable'}</span>
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

const renderGraph = (currentUserAccessRight: string, capabilities = ['INVESTIGATION_INUPDATE']) => {
  const relayEnv = createMockEnvironment();
  const resolve = (operation: OperationDescriptor) => MockPayloadGenerator.generate(operation, {
    Workspace: () => ({ id: 'investigation-1', currentUserAccessRight, graph_data: null }),
  });
  relayEnv.mock.queueOperationResolver(resolve);
  const userContext = createMockUserContext({ me: { id: 'user-1', capabilities: capabilities.map((name) => ({ name })) } });
  render(
    <ProvidersWrapper relayEnv={relayEnv} userContext={userContext}>
      <Suspense fallback="loading">
        <InvestigationGraphOf />
      </Suspense>
    </ProvidersWrapper>,
  );
};

describe('InvestigationGraph', () => {
  it('makes the graph read only for a view only member, and keeps the moves of the entities in the view', async () => {
    savedPositions.mockClear();
    renderGraph('view');
    expect(await screen.findByText('read only')).toBeInTheDocument();

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

  it('makes the graph read only for an editor without the capability to update investigations, and keeps the moves in the view', async () => {
    savedPositions.mockClear();
    renderGraph('edit', ['INVESTIGATION']);
    expect(await screen.findByText('read only')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Move an entity' }));
    expect(savedPositions).not.toHaveBeenCalled();
  });

  it('leaves the graph editable for an editor holding the dashboard update capability, which the server also accepts', async () => {
    renderGraph('admin', ['EXPLORE_EXUPDATE']);
    expect(await screen.findByText('editable')).toBeInTheDocument();
  });
});
