import { fireEvent, screen } from '@testing-library/react';
import React, { type ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import CurationProposalActions from './CurationProposalActions';

// The Enterprise Edition tooltip renders a feedback form of its own, not under test here.
vi.mock('@components/common/entreprise_edition/EETooltip', () => ({
  default: ({ children }: { children: ReactNode }) => children,
}));

const proposal = {
  id: 'proposal-id',
  name: 'APT29 / Cozy Bear',
  proposal_status: 'open',
  recommended_action: 'merge',
  merge_record_id: null,
  can_apply: false,
  can_revert: false,
  adjudicable: true,
};

const renderActions = (capabilities: string[]) => testRender(
  <CurationProposalActions proposal={proposal} survivorId={null} survivorName={null} preview={null} adjudicationAvailable={true} />,
  {
    userContext: createMockUserContext({
      me: { name: 'analyst', capabilities: capabilities.map((name) => ({ name })) },
    }),
  },
);

describe('Curation proposal actions', () => {
  it('offers to ask the Curator to a user who can update knowledge', () => {
    renderActions(['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE']);
    expect(screen.getByRole('button', { name: 'Ask the Curator' })).toBeInTheDocument();
  });

  it('does not offer to ask the Curator to a user who can only read knowledge', () => {
    renderActions(['KNOWLEDGE']);
    expect(screen.queryByRole('button', { name: 'Ask the Curator' })).not.toBeInTheDocument();
  });

  it('lets a user who can update knowledge reject a merge proposal they cannot apply', () => {
    renderActions(['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE']);
    expect(screen.getByRole('button', { name: 'Reject' })).toBeInTheDocument();
    expect(screen.queryByTestId('curation-proposal-review')).not.toBeInTheDocument();
  });

  it('does not offer to reject to a user who can only read knowledge', () => {
    renderActions(['KNOWLEDGE']);
    expect(screen.queryByRole('button', { name: 'Reject' })).not.toBeInTheDocument();
  });

  it('counts the names an alias proposal of a single subject adds', () => {
    const aliasProposal = { ...proposal, name: 'Cl0p', recommended_action: 'add_aliases', can_apply: true };
    testRender(
      <CurationProposalActions
        proposal={aliasProposal}
        survivorId="cl0p"
        survivorName="Cl0p"
        preview={{ count: 0, relationships: 0, aliases: ['Clop', 'Lace Tempest'], externalReferences: 0 }}
        adjudicationAvailable={false}
      />,
      { userContext: createMockUserContext({ me: { name: 'analyst', capabilities: [{ name: 'KNOWLEDGE' }, { name: 'KNOWLEDGE_KNUPDATE' }] } }) },
    );
    fireEvent.click(screen.getByTestId('curation-proposal-review'));
    expect(screen.getByText('Add 2 names as aliases of Cl0p')).toBeInTheDocument();
  });
});
