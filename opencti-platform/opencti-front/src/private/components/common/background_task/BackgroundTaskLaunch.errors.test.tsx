import React, { useState } from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import { MESSAGING$ } from '../../../../relay/environment';
import BackgroundTaskLaunch from './BackgroundTaskLaunch';

const enrichWithHygiene = {
  type: 'ENRICHMENT' as const,
  context: { values: [{ id: 'connector-1', value: 'Hygiene' }] },
};

const apiError = (error: Record<string, unknown>) => Object.assign(new Error('rejected'), { res: { errors: [error] } });

// Closes the launcher on completion and on close, as its callers do.
const Caller = ({ confirmOnlyAboveLimit, onClose, onCompleted }: { confirmOnlyAboveLimit: boolean; onClose: () => void; onCompleted: () => void }) => {
  const [display, setDisplay] = useState(true);
  return (
    <>
      <button type="button" onClick={() => setDisplay(true)}>reopen</button>
      <BackgroundTaskLaunch
        display={display}
        processing={false}
        confirmOnlyAboveLimit={confirmOnlyAboveLimit}
        onClose={() => {
          setDisplay(false);
          onClose();
        }}
        onLaunch={() => {}}
        onCompleted={() => {
          setDisplay(false);
          onCompleted();
        }}
        selectedElements={{ 'ip-1': { id: 'ip-1', name: '8.8.8.8' } }}
        numberOfSelectedElements={1}
        taskScope="KNOWLEDGE"
        actions={[enrichWithHygiene]}
      />
    </>
  );
};

const renderCaller = (confirmOnlyAboveLimit: boolean) => {
  const onClose = vi.fn();
  const onCompleted = vi.fn();
  const { relayEnv } = testRender(<Caller confirmOnlyAboveLimit={confirmOnlyAboveLimit} onClose={onClose} onCompleted={onCompleted} />);
  return { relayEnv, onClose, onCompleted };
};

describe('BackgroundTaskLaunch, when the API answers', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('without the dialog', () => {
    it('redirects to the password change when the API requires it, and closes the launcher', () => {
      const redirect = vi.spyOn(MESSAGING$.redirect, 'next');
      const { relayEnv, onClose, onCompleted } = renderCaller(true);

      act(() => relayEnv.mock.rejectMostRecentOperation(apiError({ message: 'Password change required', extensions: { code: 'PASSWORD_CHANGE_REQUIRED' } })));

      expect(redirect).toHaveBeenCalledWith('/dashboard/change-password');
      expect(onClose).toHaveBeenCalledTimes(1);
      expect(onCompleted).not.toHaveBeenCalled();
    });

    it('asks to refresh the browser on an authentication error, and closes the launcher', () => {
      const notifyError = vi.spyOn(MESSAGING$, 'notifyError');
      const { relayEnv, onClose } = renderCaller(true);

      act(() => relayEnv.mock.rejectMostRecentOperation(apiError({ message: 'authentication', data: { type: 'authentication' } })));

      expect(notifyError).toHaveBeenCalledWith('Unauthorized action, please refresh your browser');
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('shows the error of a rejected task and closes the launcher, so that the next display launches again', () => {
      const messages = vi.spyOn(MESSAGING$.messages, 'next');
      const { relayEnv, onClose, onCompleted } = renderCaller(true);

      act(() => relayEnv.mock.rejectMostRecentOperation(apiError({ message: 'Task rejected' })));

      expect(messages).toHaveBeenCalledWith([{ type: 'error', text: 'Task rejected' }]);
      expect(onClose).toHaveBeenCalledTimes(1);
      expect(onCompleted).not.toHaveBeenCalled();

      fireEvent.click(screen.getByText('reopen'));
      expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    });

    it('does not close the launcher once more after the task is created', () => {
      const { relayEnv, onClose, onCompleted } = renderCaller(true);

      act(() => relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation)));

      expect(onCompleted).toHaveBeenCalledTimes(1);
      expect(onClose).not.toHaveBeenCalled();
    });
  });

  it('keeps the confirmation dialog open when the API rejects the task', () => {
    const messages = vi.spyOn(MESSAGING$.messages, 'next');
    const { relayEnv, onClose } = renderCaller(false);
    fireEvent.click(screen.getByRole('button', { name: 'Launch' }));

    act(() => relayEnv.mock.rejectMostRecentOperation(apiError({ message: 'Task rejected' })));

    expect(messages).toHaveBeenCalledWith([{ type: 'error', text: 'Task rejected' }]);
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByTestId('background-task-popup')).toBeInTheDocument();
  });
});
