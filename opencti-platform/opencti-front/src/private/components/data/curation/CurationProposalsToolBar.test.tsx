import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import CurationProposalsToolBar from './CurationProposalsToolBar';

const commitAccept = vi.fn();
const commitReject = vi.fn();
let selectedElements: Record<string, { id: string; proposal_status: string; choice_required: boolean; can_apply?: boolean }> = {};

vi.mock('../../../../components/dataGrid/components/DataTableContext', () => ({
  useDataTableContext: () => ({
    useDataTableToggle: {
      selectedElements,
      numberOfSelectedElements: Object.keys(selectedElements).length,
      handleClearSelectedElements: vi.fn(),
    },
  }),
}));

// The toolbar declares the accept mutation, then the reject one, at every render.
let mutationCalls = 0;
vi.mock('../../../../utils/hooks/useApiMutation', () => ({
  default: () => {
    mutationCalls += 1;
    return [mutationCalls % 2 === 1 ? commitAccept : commitReject, false];
  },
}));

const select = (...proposals: Array<{ id: string; proposal_status?: string; choice_required?: boolean; can_apply?: boolean }>) => {
  selectedElements = Object.fromEntries(proposals.map((proposal) => [proposal.id, { proposal_status: 'open', choice_required: false, ...proposal }]));
};

describe('Curation proposals toolbar', () => {
  beforeEach(() => {
    commitAccept.mockReset();
    commitReject.mockReset();
    mutationCalls = 0;
  });

  it('leaves the proposals that need a choice out of a bulk accept, and says so', () => {
    select({ id: 'alias-proposal' }, { id: 'attribution-proposal', choice_required: true });
    testRender(<CurationProposalsToolBar onDone={vi.fn()} />);

    expect(screen.getByTestId('curation-proposals-choice-required')).toHaveTextContent(
      '1 selected proposal needs the attribution to keep: open it to accept it',
    );
    fireEvent.click(screen.getByRole('button', { name: 'Accept' }));
    expect(commitAccept).toHaveBeenCalledWith(expect.objectContaining({ variables: { ids: ['alias-proposal'] } }));
  });

  it('leaves the proposals the user cannot apply out of a bulk accept, and says so', () => {
    select({ id: 'alias-proposal' }, { id: 'merge-proposal', can_apply: false });
    testRender(<CurationProposalsToolBar onDone={vi.fn()} />);

    expect(screen.getByTestId('curation-proposals-not-applicable')).toHaveTextContent(
      '1 selected proposal needs a capability you do not have: it is left out of the accept',
    );
    fireEvent.click(screen.getByRole('button', { name: 'Accept' }));
    expect(commitAccept).toHaveBeenCalledWith(expect.objectContaining({ variables: { ids: ['alias-proposal'] } }));
  });

  it('keeps the accept disabled when every open selected proposal needs a choice, and still lets them be rejected', () => {
    select({ id: 'attribution-proposal', choice_required: true }, { id: 'decided-proposal', proposal_status: 'accepted' });
    testRender(<CurationProposalsToolBar onDone={vi.fn()} />);

    expect(screen.getByRole('button', { name: 'Accept' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Reject' })).toBeEnabled();
  });

  const openRejectDialog = () => {
    fireEvent.click(screen.getByRole('button', { name: 'Reject' }));
    return screen.getByLabelText('Rationale (optional)');
  };

  it('keeps the rationale of a refused bulk rejection for the retry, and clears it once the rejection succeeded', async () => {
    select({ id: 'stale-proposal' });
    testRender(<CurationProposalsToolBar onDone={vi.fn()} />);

    fireEvent.change(openRejectDialog(), { target: { value: 'Still active in 2026' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Reject' }).at(-1) as HTMLElement);
    await waitFor(() => expect(commitReject).toHaveBeenCalledTimes(1));
    expect(commitReject.mock.calls[0][0].variables).toEqual({ ids: ['stale-proposal'], rationale: 'Still active in 2026' });

    act(() => commitReject.mock.calls[0][0].onCompleted({ curationProposalsBulkReject: [] }, [{ message: 'Refused' }]));
    expect(screen.getByLabelText('Rationale (optional)')).toHaveValue('Still active in 2026');

    fireEvent.click(screen.getAllByRole('button', { name: 'Reject' }).at(-1) as HTMLElement);
    await waitFor(() => expect(commitReject).toHaveBeenCalledTimes(2));
    act(() => commitReject.mock.calls[1][0].onCompleted({ curationProposalsBulkReject: [{ id: 'stale-proposal' }] }, null));
    await waitFor(() => expect(screen.queryByLabelText('Rationale (optional)')).not.toBeInTheDocument());
    expect(openRejectDialog()).toHaveValue('');
  });

  it('clears the rationale when the rejection is cancelled', () => {
    select({ id: 'stale-proposal' });
    testRender(<CurationProposalsToolBar onDone={vi.fn()} />);

    fireEvent.change(openRejectDialog(), { target: { value: 'Not sure yet' } });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(openRejectDialog()).toHaveValue('');
    expect(commitReject).not.toHaveBeenCalled();
  });

  it('accepts every open proposal when none needs a choice', () => {
    select({ id: 'alias-proposal' }, { id: 'stale-proposal' });
    testRender(<CurationProposalsToolBar onDone={vi.fn()} />);

    expect(screen.queryByTestId('curation-proposals-choice-required')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Accept' }));
    expect(commitAccept).toHaveBeenCalledWith(expect.objectContaining({ variables: { ids: ['alias-proposal', 'stale-proposal'] } }));
  });
});
