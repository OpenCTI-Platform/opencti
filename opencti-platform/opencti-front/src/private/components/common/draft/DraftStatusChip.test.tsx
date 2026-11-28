import { describe, it, expect } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import DraftStatusChip from './DraftStatusChip';
import testRender from '../../../../utils/tests/test-render';

const inProgress = { id: 'status-1', template: { name: 'IN_PROGRESS', color: '#ff0000' } };

describe('DraftStatusChip', () => {
  it('shows the workflow status of an open draft', () => {
    testRender(<DraftStatusChip draftStatus="open" workflowCurrentStatus={inProgress} />);
    expect(screen.getByText(/in_progress/i)).toBeInTheDocument();
  });

  it('shows validated for a validated draft, whatever its workflow status', () => {
    testRender(<DraftStatusChip draftStatus="validated" workflowCurrentStatus={inProgress} />);
    expect(screen.getByText('validated')).toBeInTheDocument();
    expect(screen.queryByText(/in_progress/i)).not.toBeInTheDocument();
  });
});
