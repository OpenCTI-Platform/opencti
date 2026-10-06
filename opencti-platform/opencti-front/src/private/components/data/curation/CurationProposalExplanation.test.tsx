import { screen, within } from '@testing-library/react';
import React from 'react';
import { describe, expect, it } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import CurationProposalExplanation, { type CurationExplanationData, type CurationExplanationMessage } from './CurationProposalExplanation';

const explanationMessage = (template: string, values: Record<string, string | number> = {}): CurationExplanationMessage => ({
  template,
  values: JSON.stringify(values),
  text: template.replace(/\{(\w+)\}/g, (_, key: string) => String(values[key])),
});

// The explanation the platform builds for the alias proposal of APT28.
const aliasExplanation: CurationExplanationData = {
  title: explanationMessage('Add {count} aliases to {name}', { count: 3, name: 'APT28' }),
  changes: [{ field: explanationMessage('Aliases'), before: ['Sofacy'], after: ['Sofacy', 'Fancy Bear', 'Sednit', 'Forest Blizzard'] }],
  evidence: [
    {
      message: explanationMessage('MITRE ATT&CK lists {count} of these names under {reference} ("{matched}"): {names}', {
        count: 2, reference: 'G0007', matched: 'APT28', names: 'Fancy Bear, Sednit',
      }),
      entities: [],
      sources: [{ name: 'MITRE ATT&CK', reference: 'G0007', url: 'https://attack.mitre.org/groups/G0007/' }],
    },
    { message: explanationMessage('No other entity in this platform carries any of these names.'), entities: [], sources: [] },
  ],
  why: explanationMessage(
    'Security vendors give {name} different names. These names come from the public catalogues of threat names shipped with OpenCTI (copy of {catalogueDate}), cited in the evidence: they were not read from your data or from another OpenCTI platform. As aliases, they let search, imports and duplicate detection recognize {name} under each of them.',
    { name: 'APT28', catalogueDate: '2026-10-03' },
  ),
  confidence: { score: 0.86, level: 'high', meaning: explanationMessage('High ({percent}%): the evidence is strong and consistent.', { percent: 86 }) },
  on_accept: explanationMessage('The names are added to the aliases of {name}. Nothing else changes. You can undo it later with Revert on this proposal.', { name: 'APT28' }),
  on_reject: explanationMessage('Nothing changes. The same names are not proposed again for {name}.', { name: 'APT28' }),
  on_later: explanationMessage('Nothing changes. The proposal stays open in Data > Curation until someone decides.'),
  reversible: true,
};

describe('Curation proposal explanation', () => {
  it('shows what changes, with the added values next to the current ones', () => {
    testRender(<CurationProposalExplanation explanation={aliasExplanation} />);
    const change = screen.getByTestId('curation-explanation-change');
    expect(within(change).getByText('Aliases')).toBeInTheDocument();
    expect(within(screen.getByTestId('curation-explanation-before')).getByText('Sofacy')).toBeInTheDocument();
    const after = screen.getByTestId('curation-explanation-after');
    ['Sofacy', 'Fancy Bear', 'Sednit', 'Forest Blizzard'].forEach((name) => expect(within(after).getByText(name)).toBeInTheDocument());
  });

  it('shows the names and aliases spelled as they are stored', () => {
    const changes = [{ field: explanationMessage('Aliases'), before: ['sofacy'], after: ['sofacy', 'fancy-bear'] }];
    testRender(<CurationProposalExplanation explanation={{ ...aliasExplanation, changes }} />);
    const after = screen.getByTestId('curation-explanation-after');
    ['sofacy', 'fancy-bear'].forEach((name) => {
      expect(within(after).getByText(name).closest('[style*="text-transform"]')).toHaveStyle({ textTransform: 'none' });
    });
  });

  it('cites the catalogue entries behind the names, with a link to each', () => {
    testRender(<CurationProposalExplanation explanation={aliasExplanation} />);
    const evidence = screen.getByTestId('curation-explanation-evidence');
    expect(within(evidence).getByText(/MITRE ATT&CK lists 2 of these names under G0007 \("APT28"\): Fancy Bear, Sednit/)).toBeInTheDocument();
    expect(within(evidence).getByRole('link', { name: 'MITRE ATT&CK G0007' })).toHaveAttribute('href', 'https://attack.mitre.org/groups/G0007/');
    expect(within(evidence).getByText('No other entity in this platform carries any of these names.')).toBeInTheDocument();
  });

  it('says why in plain language, where the names come from, what the confidence means and what each decision does', () => {
    testRender(<CurationProposalExplanation explanation={aliasExplanation} />);
    const why = screen.getByTestId('curation-explanation-why');
    expect(why).toHaveTextContent('they were not read from your data or from another OpenCTI platform');
    expect(why).not.toHaveTextContent(/instance|detector|candidate/i);
    expect(screen.getByTestId('curation-explanation-confidence')).toHaveTextContent('High (86%): the evidence is strong and consistent.');
    const outcomes = screen.getByTestId('curation-explanation-outcomes');
    expect(outcomes).toHaveTextContent('You can undo it later with Revert on this proposal.');
    expect(outcomes).toHaveTextContent('Nothing changes. The same names are not proposed again for APT28.');
    expect(outcomes).toHaveTextContent('Nothing changes. The proposal stays open in Data > Curation until someone decides.');
  });

  it('links the entities an evidence names, and fills a change left to the analyst with the choice made on screen', () => {
    const attribution: CurationExplanationData = {
      ...aliasExplanation,
      changes: [{ field: explanationMessage('Attributed to'), before: ['APT28', 'APT29'], after: [] }],
      evidence: [{
        message: explanationMessage('"{attributed}" is attributed to {actors}, actors that were decided to be distinct, and no source attributes it to all of them', {
          attributed: 'Operation X', actors: '"APT28", "APT29"',
        }),
        entities: [{ id: 'apt28-id', name: 'APT28', entity_type: 'Intrusion-Set' }],
        sources: [],
      }],
    };
    const { rerender } = testRender(<CurationProposalExplanation explanation={attribution} />);
    expect(within(screen.getByTestId('curation-explanation-after')).getByText('To choose')).toBeInTheDocument();
    expect(within(screen.getByTestId('curation-explanation-evidence')).getByRole('link', { name: 'APT28' }))
      .toHaveAttribute('href', '/dashboard/threats/intrusion_sets/apt28-id');
    rerender(<CurationProposalExplanation explanation={attribution} chosen="APT29" />);
    expect(within(screen.getByTestId('curation-explanation-after')).getByText('APT29')).toBeInTheDocument();
  });

  it('separates the entities an evidence names from its sentence and from each other', () => {
    const merge: CurationExplanationData = {
      ...aliasExplanation,
      evidence: [{
        message: explanationMessage('The source {sources} maintains both entities separately, which suggests they are distinct', { sources: '"Mandiant"' }),
        entities: [{ id: 'apt28-id', name: 'APT28', entity_type: 'Intrusion-Set' }, { id: 'fancy-id', name: 'Fancy Bear', entity_type: 'Intrusion-Set' }],
        sources: [],
      }],
    };
    testRender(<CurationProposalExplanation explanation={merge} />);
    expect(screen.getByTestId('curation-explanation-evidence-entities')).toHaveTextContent(/^- APT28, Fancy Bear$/);
  });

  it('translates the values by kind: entity types, attributes and dates', () => {
    const fixDates: CurationExplanationData = {
      ...aliasExplanation,
      title: explanationMessage('Swap the {startField} and {stopField} dates of "{name}"', { startField: 'first_seen', stopField: 'last_seen', name: 'Operation X' }),
      changes: [{ field: explanationMessage('{field}', { field: 'first_seen' }), before: ['2024-05-01'], after: ['2023-01-01'] }],
      evidence: [],
    };
    testRender(<CurationProposalExplanation explanation={fixDates} />);
    expect(within(screen.getByTestId('curation-explanation-change')).getByText('First seen')).toBeInTheDocument();
  });
});
