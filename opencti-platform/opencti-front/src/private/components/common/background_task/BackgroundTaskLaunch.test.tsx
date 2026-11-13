import React from 'react';
import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import BackgroundTaskLaunch from './BackgroundTaskLaunch';

const mocks = vi.hoisted(() => ({
  listTaskAdd: vi.fn(),
}));

vi.mock('../../../../utils/hooks/useApiMutation', () => ({
  default: () => [mocks.listTaskAdd],
}));

describe('BackgroundTaskLaunch', () => {
  it('shows the name of a value given as { id, value }, and sends only its id', () => {
    testRender(
      <BackgroundTaskLaunch
        display
        processing={false}
        onClose={() => {}}
        onLaunch={() => {}}
        onCompleted={() => {}}
        selectedElements={{ 'ip-1': { id: 'ip-1', name: '8.8.8.8' } }}
        numberOfSelectedElements={1}
        taskScope="KNOWLEDGE"
        actions={[{
          type: 'ENRICHMENT',
          context: { values: [{ id: 'connector-1', value: 'Hygiene' }], options: { investigationId: 'investigation-1' } },
        }]}
      />,
    );

    expect(screen.getByText('Hygiene')).toBeInTheDocument();
    expect(screen.queryByText('connector-1')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Launch' }));

    expect(mocks.listTaskAdd).toHaveBeenCalledTimes(1);
    expect(mocks.listTaskAdd.mock.calls[0][0].variables.input).toMatchObject({
      ids: ['ip-1'],
      actions: [{
        type: 'ENRICHMENT',
        context: { values: ['connector-1'], options: { investigationId: 'investigation-1' } },
      }],
    });
  });
});
