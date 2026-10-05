import { fireEvent, screen, within } from '@testing-library/react';
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

  describe('with the explanation of the proposal', () => {
    const message = (template: string, values: Record<string, string | number> = {}) => ({
      template,
      values: JSON.stringify(values),
      text: template.replace(/\{(\w+)\}/g, (_, key: string) => String(values[key])),
    });
    const explanation = {
      title: message('Add {count} aliases to {name}', { count: 2, name: 'APT28' }),
      changes: [{ field: message('Aliases'), before: ['Sofacy'], after: ['Sofacy', 'Fancy Bear', 'Sednit'] }],
      evidence: [{
        message: message('MITRE ATT&CK lists {count} of these names under {reference} ("{matched}"): {names}', { count: 2, reference: 'G0007', matched: 'APT28', names: 'Fancy Bear, Sednit' }),
        entities: [],
        sources: [{ name: 'MITRE ATT&CK', reference: 'G0007', url: 'https://attack.mitre.org/groups/G0007/' }],
      }],
      why: message('Security vendors give {name} different names. These names come from the public catalogues of threat names shipped with OpenCTI (copy of {catalogueDate}), cited in the evidence: they were not read from your data or from another OpenCTI platform. As aliases, they let search, imports and duplicate detection recognize {name} under each of them.', { name: 'APT28', catalogueDate: '2026-10-03' }),
      confidence: { score: 0.86, level: 'high', meaning: message('High ({percent}%): the evidence is strong and consistent.', { percent: 86 }) },
      on_accept: message('The names are added to the aliases of {name}. Nothing else changes. You can undo it later with Revert on this proposal.', { name: 'APT28' }),
      on_reject: message('Nothing changes. The same names are not proposed again for {name}.', { name: 'APT28' }),
      on_later: message('Nothing changes. The proposal stays open in Data > Curation until someone decides.'),
      reversible: true,
    };
    const analyst = createMockUserContext({ me: { name: 'analyst', capabilities: [{ name: 'KNOWLEDGE' }, { name: 'KNOWLEDGE_KNUPDATE' }] } });
    const aliasProposal = { ...proposal, name: 'APT28', recommended_action: 'add_aliases', can_apply: true };

    it('titles the approval with what changes and explains the evidence, the reason and each decision', () => {
      testRender(
        <CurationProposalActions
          proposal={aliasProposal}
          survivorId="apt28"
          survivorName="APT28"
          preview={{ count: 0, relationships: 0, aliases: ['Fancy Bear', 'Sednit'], externalReferences: 0 }}
          adjudicationAvailable={false}
          explanation={explanation}
        />,
        { userContext: analyst },
      );
      fireEvent.click(screen.getByTestId('curation-proposal-review'));
      const dialog = screen.getByRole('dialog');
      expect(within(dialog).getByText('Add 2 aliases to APT28')).toBeInTheDocument();
      expect(within(dialog).getByTestId('curation-explanation-changes')).toHaveTextContent('Fancy Bear');
      expect(within(dialog).getByRole('link', { name: 'MITRE ATT&CK G0007' })).toHaveAttribute('href', 'https://attack.mitre.org/groups/G0007/');
      expect(within(dialog).getByTestId('curation-explanation-why')).toHaveTextContent('not read from your data or from another OpenCTI platform');
      expect(within(dialog).getByTestId('curation-explanation-confidence')).toHaveTextContent('High (86%)');
      expect(within(dialog).getByTestId('curation-explanation-outcomes')).toHaveTextContent('You can undo it later with Revert on this proposal.');
      expect(dialog).not.toHaveTextContent(/\binstances?\b|detector|candidate/i);
    });

    it('says what a rejection does', () => {
      testRender(
        <CurationProposalActions proposal={aliasProposal} survivorId="apt28" survivorName="APT28" preview={null} adjudicationAvailable={false} explanation={explanation} />,
        { userContext: analyst },
      );
      fireEvent.click(screen.getByRole('button', { name: 'Reject' }));
      expect(within(screen.getByRole('dialog')).getByText(/Nothing changes\. The same names are not proposed again for APT28\./)).toBeInTheDocument();
    });

    it('keeps the survivor chosen on screen in the title of a merge', () => {
      const mergeProposal = { ...proposal, can_apply: true };
      testRender(
        <CurationProposalActions
          proposal={mergeProposal}
          survivorId="apt29"
          survivorName="APT29"
          preview={{ count: 1, relationships: 3, aliases: ['Cozy Bear'], externalReferences: 1 }}
          adjudicationAvailable={false}
          explanation={{ ...explanation, title: message('Merge "{other}" into "{target}"', { other: 'Cozy Bear', target: 'APT29' }) }}
        />,
        { userContext: createMockUserContext({ me: { name: 'analyst', capabilities: [{ name: 'KNOWLEDGE' }, { name: 'KNOWLEDGE_KNUPDATE' }, { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }] } }) },
      );
      fireEvent.click(screen.getByTestId('curation-proposal-review'));
      const dialog = screen.getByRole('dialog');
      expect(within(dialog).getByText('Merge 1 object into APT29')).toBeInTheDocument();
      expect(within(dialog).getByTestId('curation-merge-preview')).toHaveTextContent('3 relationships move to APT29');
    });
  });
});
