import { describe, expect, it } from 'vitest';
import { buildMergePreview } from './CurationProposalCompare';
import type { CurationProposalCompare_proposal$data } from './__generated__/CurationProposalCompare_proposal.graphql';

const subject = (id: string, name: string, aliases: string[], connected = 0) => ({
  id,
  entity_type: 'Intrusion-Set',
  representative: { main: name },
  numberOfConnectedElement: connected,
  toStix: JSON.stringify({ name, aliases, external_references: [{ source_name: 'vendor' }] }),
});

const proposalOf = (subjects: ReturnType<typeof subject>[]) => ({
  id: 'proposal-1',
  subject_ids: subjects.map((s) => s.id),
  subjects,
}) as unknown as CurationProposalCompare_proposal$data;

describe('buildMergePreview', () => {
  it('moves the names, relationships and references of the other subjects of a merge', () => {
    const proposal = proposalOf([subject('apt29', 'APT29', ['The Dukes']), subject('cozy', 'Cozy Bear', ['the dukes', 'CozyDuke'], 4)]);
    expect(buildMergePreview(proposal, 'apt29')).toEqual({ count: 1, relationships: 4, aliases: ['Cozy Bear', 'CozyDuke'], externalReferences: 1 });
  });

  it('lists the aliases an alias proposal adds to its single subject, without the names it already has', () => {
    const proposal = proposalOf([subject('cl0p', 'Cl0p', ['TA505'])]);
    expect(buildMergePreview(proposal, 'cl0p', ['Clop', 'ta505', 'Lace Tempest'])).toEqual({
      count: 0,
      relationships: 0,
      aliases: ['Clop', 'Lace Tempest'],
      externalReferences: 0,
    });
  });

  it('has nothing to preview without a survivor among the subjects', () => {
    const proposal = proposalOf([subject('cl0p', 'Cl0p', [])]);
    expect(buildMergePreview(proposal, null, ['Clop'])).toBeNull();
    expect(buildMergePreview(proposal, 'unknown', ['Clop'])).toBeNull();
  });
});
