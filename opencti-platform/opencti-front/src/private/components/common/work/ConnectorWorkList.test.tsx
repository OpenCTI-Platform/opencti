import React, { ReactNode } from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import ConnectorWorkList, { ConnectorWorkListItem } from './ConnectorWorkList';

vi.mock('../../../../utils/Security', () => ({
  default: ({ children }: { children: ReactNode }) => children,
}));

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
    testRender(
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
    testRender(
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
    testRender(
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
    testRender(
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
    const { relayEnv } = testRender(
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
});
