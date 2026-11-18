import React, { ReactElement } from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ConnectorWorkList, { ConnectorWorkListItem } from './ConnectorWorkList';

// A connector manager without BYPASS, so that the capabilities the actions need are really checked.
const renderList = (ui: ReactElement) => testRender(ui, {
  userContext: createMockUserContext({
    me: { id: 'user-1', capabilities: ['MODULES_MODMANAGE', 'KNOWLEDGE_KNENRICHMENT'].map((name) => ({ name })) },
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

  it('offers adding all the results and marking them as reviewed to a member who can review them', () => {
    renderList(
      <ConnectorWorkList
        items={[connectorItem([{ id: 'work-1', status: 'complete' }])]}
        onRefresh={vi.fn()}
        onWorkDeleted={vi.fn()}
        onReview={vi.fn()}
        onReviewAddAll={vi.fn()}
        onReviewDismiss={vi.fn()}
        canEditInvestigation
      />,
    );

    ['Review results', 'Add all to graph', 'Mark as reviewed', 'Delete'].forEach((name) => {
      expect(screen.getByRole('button', { name })).toBeInTheDocument();
    });
  });

  it('runs the review actions on the clicked work', () => {
    const onReview = vi.fn();
    const onReviewAddAll = vi.fn();
    const onReviewDismiss = vi.fn();
    renderList(
      <ConnectorWorkList
        items={[connectorItem([{ id: 'work-1', status: 'complete' }])]}
        onRefresh={vi.fn()}
        onWorkDeleted={vi.fn()}
        onReview={onReview}
        onReviewAddAll={onReviewAddAll}
        onReviewDismiss={onReviewDismiss}
        canEditInvestigation
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Review results' }));
    fireEvent.click(screen.getByRole('button', { name: 'Add all to graph' }));
    fireEvent.click(screen.getByRole('button', { name: 'Mark as reviewed' }));

    expect(onReview).toHaveBeenCalledWith('work-1');
    expect(onReviewAddAll).toHaveBeenCalledWith('work-1');
    expect(onReviewDismiss).toHaveBeenCalledWith('work-1');
  });

  it('shows the messages of a work on its status and date', async () => {
    renderList(
      <ConnectorWorkList
        items={[connectorItem([{ id: 'work-1', status: 'complete', messages: [{ timestamp: '2026-11-18T10:00:00.000Z', message: 'Enrichment done' }] }])]}
        onRefresh={vi.fn()}
        onWorkDeleted={vi.fn()}
      />,
    );

    const trigger = screen.getByTestId('CheckCircleOutlinedIcon').closest('[data-state]') as HTMLElement;
    fireEvent.focus(trigger);

    expect((await screen.findAllByText(/Enrichment done/)).length).toBeGreaterThan(0);
  });

  it('hides adding all the results and marking them as reviewed from a member who cannot review them', () => {
    renderList(
      <ConnectorWorkList
        items={[connectorItem([{ id: 'work-1', status: 'complete' }])]}
        onRefresh={vi.fn()}
        onWorkDeleted={vi.fn()}
        onReview={vi.fn()}
        onReviewAddAll={vi.fn()}
        onReviewDismiss={vi.fn()}
      />,
    );

    expect(screen.getByRole('button', { name: 'Review results' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add all to graph' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Mark as reviewed' })).not.toBeInTheDocument();
  });

  it('hides Delete for a member who cannot delete the works, keeping the review of the results', () => {
    renderList(
      <ConnectorWorkList
        items={[connectorItem([{ id: 'work-1', status: 'complete' }])]}
        onRefresh={vi.fn()}
        onWorkDeleted={vi.fn()}
        onReview={vi.fn()}
        canDelete={false}
      />,
    );

    expect(screen.getByRole('button', { name: 'Review results' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });
});
