import React, { ReactNode } from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ConnectorWorkList, { ConnectorWorkListItem } from './ConnectorWorkList';

/**
 * Renders the list for a user, not a bypass one, allowed to refresh the knowledge and to manage the works.
 */
const renderList = (ui: ReactNode) => testRender(ui, {
  userContext: createMockUserContext({
    me: { id: 'user-1', capabilities: [{ name: 'KNOWLEDGE_KNENRICHMENT' }, { name: 'MODULES_MODMANAGE' }] },
  }),
});

/**
 * Builds a list item for one active enrichment connector with the given works.
 */
const connectorItem = (works: ConnectorWorkListItem['works']): ConnectorWorkListItem => ({
  connector: {
    id: 'connector-1',
    name: 'Coucou enrichment',
    active: true,
    connector_type: 'INTERNAL_ENRICHMENT',
  },
  works,
});

describe('ConnectorWorkList', () => {
  it('tells when there is no connector', () => {
    renderList(
      <ConnectorWorkList
        items={[]}
        onRefresh={vi.fn()}
        onWorkDeleted={vi.fn()}
      />,
    );

    expect(screen.getByText('No connectors for this type of entity')).toBeInTheDocument();
  });

  it('refreshes the knowledge with the clicked connector', () => {
    const onRefresh = vi.fn();
    const item = connectorItem([]);
    renderList(
      <ConnectorWorkList
        items={[item]}
        onRefresh={onRefresh}
        onWorkDeleted={vi.fn()}
      />,
    );

    expect(screen.getByText('Coucou enrichment')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Refresh the knowledge using this connector' }));

    expect(onRefresh).toHaveBeenCalledWith(item.connector);
  });

  it('hides the refresh when the connectors cannot be run again', () => {
    renderList(
      <ConnectorWorkList
        items={[connectorItem([])]}
        onRefresh={vi.fn()}
        canRefresh={false}
        onWorkDeleted={vi.fn()}
      />,
    );

    expect(screen.getByText('Coucou enrichment')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Refresh the knowledge using this connector' })).not.toBeInTheDocument();
  });

  it('disables the refresh while a work of the connector is not complete', () => {
    renderList(
      <ConnectorWorkList
        items={[connectorItem([{ id: 'work-1', status: 'progress' }])]}
        onRefresh={vi.fn()}
        onWorkDeleted={vi.fn()}
      />,
    );

    expect(screen.getByRole('button', { name: 'Refresh the knowledge using this connector' })).toBeDisabled();
  });

  it('deletes the clicked work then notifies the parent', () => {
    const onWorkDeleted = vi.fn();
    const { relayEnv } = renderList(
      <ConnectorWorkList
        items={[connectorItem([{ id: 'work-1', status: 'complete' }])]}
        onRefresh={vi.fn()}
        onWorkDeleted={onWorkDeleted}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.operation.name).toBe('ConnectorWorkListDeleteMutation');
    expect(operation.request.variables).toEqual({ workId: 'work-1' });
    expect(onWorkDeleted).not.toHaveBeenCalled();

    act(() => {
      relayEnv.mock.resolve(operation, MockPayloadGenerator.generate(operation));
    });

    expect(onWorkDeleted).toHaveBeenCalledOnce();
  });

  it('lets an editor allowed to review add all the results or mark them as reviewed', async () => {
    const onReviewAddAll = vi.fn();
    const onReviewDismiss = vi.fn();
    const { user } = renderList(
      <ConnectorWorkList
        items={[connectorItem([{ id: 'work-1', status: 'complete' }])]}
        onRefresh={vi.fn()}
        onReview={vi.fn()}
        onReviewAddAll={onReviewAddAll}
        onReviewDismiss={onReviewDismiss}
        canEditInvestigation
      />,
    );

    await user.click(screen.getByRole('button', { name: 'Add all to graph' }));
    await user.click(screen.getByRole('button', { name: 'Mark as reviewed' }));

    expect(onReviewAddAll).toHaveBeenCalledWith('work-1');
    expect(onReviewDismiss).toHaveBeenCalledWith('work-1');
  });

  it('disables the review actions of an editor who cannot review the results, saying why, from the keyboard too', async () => {
    const onReview = vi.fn();
    const onReviewAddAll = vi.fn();
    const onReviewDismiss = vi.fn();
    const { user } = renderList(
      <ConnectorWorkList
        items={[connectorItem([{ id: 'work-1', status: 'complete' }])]}
        onRefresh={vi.fn()}
        onReview={onReview}
        onReviewAddAll={onReviewAddAll}
        onReviewDismiss={onReviewDismiss}
        canEditInvestigation
        reviewDisabledReason="Missing capabilities"
      />,
    );

    for (const name of ['Review results', 'Add all to graph', 'Mark as reviewed']) {
      const action = screen.getByRole('button', { name });
      expect(action).toHaveAttribute('aria-disabled', 'true');
      expect(action).toHaveAttribute('tabindex', '0');
      expect(action).toHaveAccessibleDescription('Missing capabilities');
      await user.click(action);
    }
    expect(onReview).not.toHaveBeenCalled();
    expect(onReviewAddAll).not.toHaveBeenCalled();
    expect(onReviewDismiss).not.toHaveBeenCalled();
  });

  it('lets a view only member open the review of a result, but neither add it nor mark it as reviewed', () => {
    const onReview = vi.fn();
    renderList(
      <ConnectorWorkList
        items={[connectorItem([{ id: 'work-1', status: 'complete' }])]}
        onRefresh={vi.fn()}
        onReview={onReview}
        onReviewAddAll={vi.fn()}
        onReviewDismiss={vi.fn()}
        canEditInvestigation={false}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Review results' }));
    expect(onReview).toHaveBeenCalledWith('work-1');
    expect(screen.queryByRole('button', { name: 'Add all to graph' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Mark as reviewed' })).not.toBeInTheDocument();
  });

  it('shows the messages of a work on its date, not over the tooltips of its actions', async () => {
    const workWithMessage = connectorItem([{ id: 'work-1', status: 'complete', timestamp: '2026-11-12T10:00:00.000Z', messages: [{ timestamp: '2026-11-12T10:00:01.000Z', message: 'Connector ready' }] }]);
    const list = <ConnectorWorkList items={[workWithMessage]} onRefresh={vi.fn()} />;

    const onDate = renderList(list);
    await onDate.user.hover(screen.getByText(/2026/));
    expect(await screen.findAllByText(/Connector ready/)).not.toHaveLength(0);
    onDate.unmount();

    const onAction = renderList(list);
    await onAction.user.hover(screen.getByRole('button', { name: 'Delete' }).parentElement!);
    expect(await screen.findAllByText('Delete')).not.toHaveLength(0);
    expect(screen.queryByText(/Connector ready/)).toBeNull();
  });
});
