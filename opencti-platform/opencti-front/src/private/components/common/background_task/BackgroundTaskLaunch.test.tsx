import React, { ComponentProps } from 'react';
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

type LauncherProps = ComponentProps<typeof BackgroundTaskLaunch>;

const launcher = (props: Partial<LauncherProps> = {}) => (
  <BackgroundTaskLaunch
    display
    processing={false}
    onClose={() => {}}
    onLaunch={() => {}}
    onCompleted={() => {}}
    selectedElements={{ 'ip-1': { id: 'ip-1', name: '8.8.8.8' } }}
    numberOfSelectedElements={1}
    taskScope="KNOWLEDGE"
    actions={[enrichWithHygiene]}
    {...props}
  />
);

const sentInput = () => {
  expect(mocks.taskAdd).toHaveBeenCalledTimes(1);
  return mocks.taskAdd.mock.calls[0][0].variables.input;
};

const confirmationDialog = () => screen.queryByTestId('background-task-popup');

describe('BackgroundTaskLaunch', () => {
  afterEach(() => {
    mocks.taskAdd.mockReset();
  });

  it('shows the name of a value given as { id, value }, and sends only its id', () => {
    testRender(launcher());

    expect(screen.getByText('Hygiene')).toBeInTheDocument();
    expect(screen.queryByText('connector-1')).not.toBeInTheDocument();
    expect(mocks.taskAdd).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'Launch' }));

    expect(sentInput()).toMatchObject({
      ids: ['ip-1'],
      actions: [{
        type: 'ENRICHMENT',
        context: { values: ['connector-1'], options: { investigationId: 'investigation-1' } },
      }],
    });
  });

  describe('when a confirmation is asked only above the limit', () => {
    it('sends nothing while it is not displayed', () => {
      const onLaunch = vi.fn();
      testRender(launcher({ confirmOnlyAboveLimit: true, display: false, onLaunch }));

      expect(confirmationDialog()).not.toBeInTheDocument();
      expect(mocks.taskAdd).not.toHaveBeenCalled();
      expect(onLaunch).not.toHaveBeenCalled();
    });

    it('launches a task on a few elements as soon as it is displayed, without the dialog', () => {
      mocks.taskAdd.mockImplementation((args) => args.onCompleted({}, null));
      const onLaunch = vi.fn();
      const onCompleted = vi.fn();
      testRender(launcher({ confirmOnlyAboveLimit: true, onLaunch, onCompleted }));

      expect(confirmationDialog()).not.toBeInTheDocument();
      expect(sentInput()).toMatchObject({
        ids: ['ip-1'],
        actions: [{ type: 'ENRICHMENT', context: { values: ['connector-1'] } }],
      });
      expect(onLaunch).toHaveBeenCalledTimes(1);
      expect(onCompleted).toHaveBeenCalledTimes(1);
    });

    it('launches without the dialog up to 1000 elements included', () => {
      testRender(launcher({ confirmOnlyAboveLimit: true, numberOfSelectedElements: 1000 }));

      expect(confirmationDialog()).not.toBeInTheDocument();
      expect(mocks.taskAdd).toHaveBeenCalledTimes(1);
    });

    it('sends the task once, without showing the dialog, even when the selection changes while it is sent', () => {
      const view = testRender(launcher({ confirmOnlyAboveLimit: true }));
      view.rerender(launcher({ confirmOnlyAboveLimit: true, processing: true, numberOfSelectedElements: 0 }));
      expect(confirmationDialog()).not.toBeInTheDocument();
      view.rerender(launcher({ confirmOnlyAboveLimit: true, processing: true, numberOfSelectedElements: 2 }));

      expect(confirmationDialog()).not.toBeInTheDocument();
      expect(mocks.taskAdd).toHaveBeenCalledTimes(1);
    });

    it('does not send the task again after a confirmation, when the selection drops below the limit while it is sent', () => {
      const view = testRender(launcher({ confirmOnlyAboveLimit: true, selectAll: true, numberOfSelectedElements: 1001 }));
      fireEvent.click(screen.getByRole('button', { name: 'Launch' }));
      view.rerender(launcher({ confirmOnlyAboveLimit: true, selectAll: true, numberOfSelectedElements: 1000, processing: true }));

      expect(mocks.taskAdd).toHaveBeenCalledTimes(1);
    });

    it('waits for the click it asked for, even when the selection drops below the limit, and decides again at the next display', () => {
      const view = testRender(launcher({ confirmOnlyAboveLimit: true, selectAll: true, numberOfSelectedElements: 1001 }));
      view.rerender(launcher({ confirmOnlyAboveLimit: true, selectAll: true, numberOfSelectedElements: 1000 }));

      expect(confirmationDialog()).toBeInTheDocument();
      expect(mocks.taskAdd).not.toHaveBeenCalled();

      view.rerender(launcher({ confirmOnlyAboveLimit: true, selectAll: true, numberOfSelectedElements: 1000, display: false }));
      view.rerender(launcher({ confirmOnlyAboveLimit: true, selectAll: true, numberOfSelectedElements: 1000 }));

      expect(mocks.taskAdd).toHaveBeenCalledTimes(1);
    });

    it('launches the task on all the elements matching the search without the dialog', () => {
      testRender(launcher({
        confirmOnlyAboveLimit: true,
        selectAll: true,
        search: '8.8',
        numberOfSelectedElements: 42,
        excludedIds: ['ip-2'],
      }));

      expect(confirmationDialog()).not.toBeInTheDocument();
      expect(sentInput()).toMatchObject({
        search: '8.8',
        excluded_ids: ['ip-2'],
        actions: [{ type: 'ENRICHMENT', context: { values: ['connector-1'] } }],
      });
    });

    it('asks for a confirmation above 1000 elements, and launches nothing before it', () => {
      const onClose = vi.fn();
      testRender(launcher({
        confirmOnlyAboveLimit: true,
        selectAll: true,
        search: '8.8',
        numberOfSelectedElements: 1001,
        onClose,
      }));

      expect(confirmationDialog()).toBeInTheDocument();
      expect(screen.getByText(/more than 1000 entities/)).toBeInTheDocument();
      expect(mocks.taskAdd).not.toHaveBeenCalled();

      mocks.taskAdd.mockImplementation((args) => args.onError?.(new Error('rejected')));
      fireEvent.click(screen.getByRole('button', { name: 'Launch' }));

      expect(sentInput()).toMatchObject({ search: '8.8' });
      expect(onClose).not.toHaveBeenCalled();
      expect(confirmationDialog()).toBeInTheDocument();
    });

    it('shows the dialog rather than launching a task on no element', () => {
      testRender(launcher({ confirmOnlyAboveLimit: true, selectAll: true, numberOfSelectedElements: 0 }));

      expect(confirmationDialog()).toBeInTheDocument();
      expect(mocks.taskAdd).not.toHaveBeenCalled();
    });

    it('closes the launcher when the API rejects the task, so that the next display launches again', () => {
      mocks.taskAdd.mockImplementation((args) => args.onError(new Error('rejected')));
      const onClose = vi.fn();
      const onCompleted = vi.fn();
      const view = testRender(launcher({ confirmOnlyAboveLimit: true, onClose, onCompleted }));

      expect(onClose).toHaveBeenCalledTimes(1);
      expect(onCompleted).not.toHaveBeenCalled();

      view.rerender(launcher({ confirmOnlyAboveLimit: true, onClose, onCompleted, display: false }));
      view.rerender(launcher({ confirmOnlyAboveLimit: true, onClose, onCompleted }));

      expect(mocks.taskAdd).toHaveBeenCalledTimes(2);
    });
  });

  it('does not close the confirmation dialog when the API rejects the task', () => {
    mocks.taskAdd.mockImplementation((args) => args.onError?.(new Error('rejected')));
    const onClose = vi.fn();
    testRender(launcher({ onClose }));

    fireEvent.click(screen.getByRole('button', { name: 'Launch' }));

    expect(mocks.taskAdd).toHaveBeenCalledTimes(1);
    expect(onClose).not.toHaveBeenCalled();
    expect(confirmationDialog()).toBeInTheDocument();
  });

  it('sends only the id of a value given as { id, value } for all the elements matching a search', () => {
    testRender(launcher({ selectAll: true, search: '8.8' }));

    expect(screen.getByText('Hygiene')).toBeInTheDocument();
    expect(screen.queryByText('connector-1')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Launch' }));

    expect(sentInput()).toMatchObject({
      search: '8.8',
      actions: [{ type: 'ENRICHMENT', context: { values: ['connector-1'], options: { investigationId: 'investigation-1' } } }],
    });
  });
});
