import React from 'react';
import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import BackgroundTaskLaunch from './BackgroundTaskLaunch';

const mocks = vi.hoisted(() => ({
  taskAdd: vi.fn(),
}));

// Both the task on selected elements and the task on all the elements matching the search use this mutation.
vi.mock('../../../../utils/hooks/useApiMutation', () => ({
  default: () => [mocks.taskAdd],
}));

const enrichWithHygiene = {
  type: 'ENRICHMENT' as const,
  context: { values: [{ id: 'connector-1', value: 'Hygiene' }], options: { investigationId: 'investigation-1' } },
};

/**
 * Renders the launcher for one enrichment, on the selected IP or on all the elements matching a search.
 */
const renderLauncher = ({ selectAll = false }: { selectAll?: boolean } = {}) => testRender(
  <BackgroundTaskLaunch
    display
    processing={false}
    onClose={() => {}}
    onLaunch={() => {}}
    onCompleted={() => {}}
    selectedElements={{ 'ip-1': { id: 'ip-1', name: '8.8.8.8' } }}
    numberOfSelectedElements={1}
    selectAll={selectAll}
    search={selectAll ? '8.8' : undefined}
    taskScope="KNOWLEDGE"
    actions={[enrichWithHygiene]}
  />,
);

/**
 * The input of the task the launcher sent.
 */
const sentInput = () => {
  expect(mocks.taskAdd).toHaveBeenCalledTimes(1);
  return mocks.taskAdd.mock.calls[0][0].variables.input;
};

describe('BackgroundTaskLaunch', () => {
  afterEach(() => {
    mocks.taskAdd.mockReset();
  });

  it('shows the name of a value given as { id, value }, and sends only its id', () => {
    renderLauncher();

    expect(screen.getByText('Hygiene')).toBeInTheDocument();
    expect(screen.queryByText('connector-1')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Launch' }));

    expect(sentInput()).toMatchObject({
      ids: ['ip-1'],
      actions: [{
        type: 'ENRICHMENT',
        context: { values: ['connector-1'], options: { investigationId: 'investigation-1' } },
      }],
    });
  });

  it('sends only the id of a value given as { id, value } for all the elements matching a search', () => {
    renderLauncher({ selectAll: true });

    expect(screen.getByText('Hygiene')).toBeInTheDocument();
    expect(screen.queryByText('connector-1')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Launch' }));

    expect(sentInput()).toMatchObject({
      search: '8.8',
      actions: [{ type: 'ENRICHMENT', context: { values: ['connector-1'], options: { investigationId: 'investigation-1' } } }],
    });
  });
});
