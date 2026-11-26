import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../utils/tests/test-render';
import ProgressBar from './ProgressBar';
import { CreationFeedbackContext } from '../utils/hooks/useCreationFeedback';

const renderWithAdd = (inProgress: boolean) => testRender(
  <CreationFeedbackContext.Provider
    value={{
      silenceCreationSuccess: true,
      bulkCreation: {
        onBulkStart: vi.fn(),
        onBulkCompleted: vi.fn(),
        onBulkEnd: vi.fn(),
        containerType: 'Report',
        progress: { done: 1, total: 2, inProgress },
        resultMessage: null,
      },
    }}
  >
    <ProgressBar open={true} value={100} title="Create multiple entities" onClose={vi.fn()} />
  </CreationFeedbackContext.Provider>,
);

const closeButton = () => screen.getByRole('button', { name: 'Close' }) as HTMLButtonElement;

describe('ProgressBar', () => {
  it('cannot be closed while the created objects are added to the container', () => {
    renderWithAdd(true);
    expect(closeButton().disabled).toBe(true);
  });

  it('can be closed once they are added', () => {
    renderWithAdd(false);
    expect(closeButton().disabled).toBe(false);
  });

  it('can be closed outside a container', () => {
    testRender(<ProgressBar open={true} value={100} title="Create multiple entities" onClose={vi.fn()} />);
    expect(closeButton().disabled).toBe(false);
  });
});
