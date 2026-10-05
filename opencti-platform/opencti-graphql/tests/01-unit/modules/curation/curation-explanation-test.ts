import { describe, expect, it } from 'vitest';
import { buildProposalExplanation, type ExplainedProposal, renderTemplate } from '../../../../src/modules/curation/curation-explanation';
import { detectMissingAliases, toCuratedEntity } from '../../../../src/modules/curation/curation-detectors';
import type { CurationEvidence } from '../../../../src/modules/curation/curation-types';

const evidenceItem = (evidenceType: string, details: Record<string, unknown>, description = 'stored description'): CurationEvidence => ({
  evidence_type: evidenceType,
  score: 1,
  weight: 0.8,
  description,
  details: JSON.stringify(details),
});

const proposal = (overrides: Partial<ExplainedProposal>): ExplainedProposal => ({
  proposal_kind: 'merge',
  recommended_action: 'merge',
  action_payload: null,
  curation_evidence: [],
  confidence_score: 0.9,
  in_ambiguous_band: false,
  subject_ids: [],
  subject_types: [],
  subject_names: [],
  target_id: null,
  ...overrides,
});

// Words that read as internal vocabulary to an analyst, or make "another platform" come to mind.
const JARGON = /\b(instance|instances|detector|candidate|cluster)\b/i;

const expectPlainLanguage = (text: string) => {
  expect(text).not.toMatch(JARGON);
  expect(text).not.toMatch(/\{\w+\}/);
};

describe('curation proposal explanations', () => {
  it('explains an alias proposal with the catalogues it comes from, never another platform', () => {
    const apt28 = toCuratedEntity({
      internal_id: 'apt28',
      standard_id: 'intrusion-set--apt28',
      entity_type: 'Intrusion-Set',
      name: 'APT28',
      aliases: ['Sofacy'],
      marking_ids: [],
      organization_ids: [],
    });
    const [draft] = detectMissingAliases([apt28]);
    const explained = buildProposalExplanation(proposal({
      proposal_kind: 'alias',
      recommended_action: 'add_aliases',
      action_payload: JSON.stringify(draft.action_payload),
      curation_evidence: draft.evidence,
      confidence_score: draft.confidence,
      subject_ids: ['apt28'],
      subject_types: ['Intrusion-Set'],
      subject_names: ['APT28'],
      target_id: 'apt28',
    }), [{ internal_id: 'apt28', entity_type: 'Intrusion-Set', name: 'APT28', aliases: ['Sofacy'] }], { catalogueVersion: '2026-10-03' });
    const added = draft.action_payload?.aliases as string[];
    expect(explained.title.text).toBe(`Add ${added.length} aliases to APT28`);
    expect(explained.changes).toEqual([{ field: expect.objectContaining({ text: 'Aliases' }), before: ['Sofacy'], after: ['Sofacy', ...added] }]);
    // Every catalogue that lists the names is cited, with a link to its entry.
    const sources = explained.evidence.flatMap((item) => item.sources);
    expect(sources).toEqual([
      { name: 'MITRE ATT&CK', reference: 'G0007', url: 'https://attack.mitre.org/groups/G0007/' },
      expect.objectContaining({ name: 'MISP galaxy (threat actors)' }),
    ]);
    expect(explained.evidence[0].message.text).toMatch(/^MITRE ATT&CK lists \d+ of these names under G0007 \("APT28"\): .*Fancy Bear/);
    expect(explained.evidence[0].entities).toEqual([]);
    expect(explained.evidence.map((item) => item.message.text)).toContain('No other entity in this platform carries any of these names.');
    expect(explained.evidence.map((item) => item.message.text).find((text) => text.startsWith('Listed by both catalogues: '))).toContain('Sednit');
    expect(explained.why.text).toContain('not read from your data or from another OpenCTI platform');
    expect(explained.why.text).toContain('copy of 2026-10-03');
    expect(explained.confidence.level).toBe('high');
    expect(explained.reversible).toBe(true);
    expect(explained.on_accept.text).toContain('Revert');
    expectPlainLanguage(explained.text);
  });

  it('counts only the names an alias proposal still adds', () => {
    const explained = buildProposalExplanation(proposal({
      proposal_kind: 'alias',
      recommended_action: 'add_aliases',
      action_payload: JSON.stringify({ aliases: ['Fancy Bear', 'Sednit'] }),
      subject_ids: ['apt28'],
      subject_names: ['APT28'],
    }), [{ internal_id: 'apt28', entity_type: 'Intrusion-Set', name: 'APT28', aliases: ['fancy bear'] }]);
    expect(explained.title.text).toBe('Add 1 alias to APT28');
    expect(explained.changes[0].after).toEqual(['fancy bear', 'Sednit']);
  });

  it('explains a merge with the surviving entity, the names it gains and how long the merge stays reversible', () => {
    const explained = buildProposalExplanation(proposal({
      subject_ids: ['a', 'b'],
      subject_types: ['Intrusion-Set', 'Intrusion-Set'],
      subject_names: ['APT28', 'APT 28'],
      target_id: 'a',
      in_ambiguous_band: true,
      confidence_score: 0.7,
      curation_evidence: [evidenceItem('canonical_collision', { canonical: 'apt28', left_name: 'APT28', right_name: 'APT 28', stripped: false })],
    }), [
      { internal_id: 'a', entity_type: 'Intrusion-Set', name: 'APT28', aliases: ['Sofacy'] },
      { internal_id: 'b', entity_type: 'Intrusion-Set', name: 'APT 28', aliases: ['Fancy Bear'] },
    ], { mergeRetentionDays: 90 });
    expect(explained.title.text).toBe('Merge "APT 28" into "APT28"');
    expect(explained.changes[0]).toEqual(expect.objectContaining({ before: ['APT28', 'APT 28'], after: ['APT28'] }));
    expect(explained.changes[1]).toEqual(expect.objectContaining({ before: ['Sofacy'], after: ['Sofacy', 'APT 28', 'Fancy Bear'] }));
    expect(explained.evidence[0].message.text).toBe('"APT28" and "APT 28" normalize to the same name "apt28" (case, punctuation, separators, digits used as letters)');
    expect(explained.evidence[0].entities.map((entity) => entity.id)).toEqual(['a', 'b']);
    expect(explained.why.text).toContain('The Intrusion Set entities "APT28" and "APT 28" carry the same name written differently');
    expect(explained.confidence.level).toBe('medium');
    expect(explained.on_accept.text).toContain('can be undone for 90 days');
    expect(explained.reversible).toBe(true);
    expectPlainLanguage(explained.text);
  });

  it('explains a merge found in a public catalogue by the catalogue, not by the spelling', () => {
    const explained = buildProposalExplanation(proposal({
      subject_ids: ['a', 'b'],
      subject_names: ['APT28', 'Fancy Bear'],
      target_id: 'a',
      curation_evidence: [evidenceItem('taxonomy', { cluster: 'mitre:G0007', source: 'mitre', left_name: 'Fancy Bear', right_name: 'APT28' })],
    }), [
      { internal_id: 'a', entity_type: 'Intrusion-Set', name: 'APT28' },
      { internal_id: 'b', entity_type: 'Intrusion-Set', name: 'Fancy Bear' },
    ]);
    expect(explained.why.text).toBe('"APT28" and "Fancy Bear" are listed as two names of the same Intrusion Set by a public catalogue of threat names shipped with OpenCTI, so they very likely describe the same thing. Two copies split its reports, indicators and relationships between them.');
    expect(explained.why.text).not.toContain('written differently');
    expect(explained.evidence[0].sources).toEqual([{ name: 'MITRE ATT&CK', reference: 'G0007', url: 'https://attack.mitre.org/groups/G0007/' }]);
  });

  it('explains a type mismatch as a review that changes nothing', () => {
    const explained = buildProposalExplanation(proposal({
      proposal_kind: 'type_mismatch',
      recommended_action: 'acknowledge',
      subject_ids: ['m', 't'],
      subject_names: ['Cobalt Strike', 'Cobalt Strike'],
      curation_evidence: [evidenceItem('type_collision', { canonical: 'cobaltstrike', left_name: 'Cobalt Strike', right_name: 'Cobalt Strike', left_type: 'Malware', right_type: 'Tool' })],
    }), [
      { internal_id: 'm', entity_type: 'Malware', name: 'Cobalt Strike' },
      { internal_id: 't', entity_type: 'Tool', name: 'Cobalt Strike' },
    ]);
    expect(explained.title.text).toBe('Check the type of "Cobalt Strike" (Malware) and "Cobalt Strike" (Tool)');
    expect(explained.changes).toEqual([]);
    expect(explained.text).toContain('What changes: nothing in the knowledge.');
    expectPlainLanguage(explained.text);
  });

  it('explains a date inversion with the dates before and after, and says it cannot be reverted', () => {
    const payload = { start_field: 'first_seen', stop_field: 'last_seen', start: '2024-05-01T00:00:00.000Z', stop: '2023-01-01T00:00:00.000Z' };
    const explained = buildProposalExplanation(proposal({
      proposal_kind: 'contradiction',
      recommended_action: 'fix_dates',
      action_payload: JSON.stringify(payload),
      subject_ids: ['c'],
      subject_names: ['Operation X'],
      curation_evidence: [evidenceItem('date_inversion', payload)],
    }), [{ internal_id: 'c', entity_type: 'Campaign', name: 'Operation X' }]);
    expect(explained.title.text).toBe('Swap the First seen and Last seen dates of "Operation X"');
    expect(explained.changes.map((change) => [change.field.text, change.before, change.after])).toEqual([
      ['First seen', ['2024-05-01'], ['2023-01-01']],
      ['Last seen', ['2023-01-01'], ['2024-05-01']],
    ]);
    expect(explained.evidence[0].message.text).toBe('First seen (2024-05-01) is after Last seen (2023-01-01)');
    expect(explained.reversible).toBe(false);
    expect(explained.on_accept.text).toContain('cannot be undone');
    expectPlainLanguage(explained.text);
  });

  it('explains an attribution conflict with every attribution in conflict', () => {
    const explained = buildProposalExplanation(proposal({
      proposal_kind: 'contradiction',
      recommended_action: 'resolve_attribution',
      action_payload: JSON.stringify({ attributed_id: 'c', relationships: [{ actor_id: 'a1', relationship_id: 'r1' }, { actor_id: 'a2', relationship_id: 'r2' }] }),
      subject_ids: ['c', 'a1', 'a2'],
      subject_names: ['Operation X', 'APT28', 'APT29'],
      curation_evidence: [evidenceItem('attribution_conflict', { attributed_name: 'Operation X', actor_names: ['APT28', 'APT29'] })],
    }), []);
    expect(explained.title.text).toBe('Keep one attribution of "Operation X"');
    expect(explained.changes[0]).toEqual(expect.objectContaining({ before: ['APT28', 'APT29'], after: [] }));
    expect(explained.evidence[0].message.text).toBe('"Operation X" is attributed to "APT28", "APT29", actors that were decided to be distinct, and no source attributes it to all of them');
    expect(explained.text).toContain('-> (to choose)');
    expectPlainLanguage(explained.text);
  });

  it('explains a revoked indicator with the observables still active', () => {
    const explained = buildProposalExplanation(proposal({
      proposal_kind: 'contradiction',
      recommended_action: 'unrevoke_indicator',
      subject_ids: ['i', 'o1'],
      subject_names: ['[ipv4-addr:value = \'1.2.3.4\']', '1.2.3.4'],
      subject_types: ['Indicator', 'IPv4-Addr'],
      curation_evidence: [evidenceItem('revoked_indicator', { indicator_name: 'bad ip', observables: [{ id: 'o1' }] })],
    }), []);
    expect(explained.title.text).toBe('Reactivate the indicator "[ipv4-addr:value = \'1.2.3.4\']"');
    expect(explained.changes[0]).toEqual(expect.objectContaining({ before: ['Yes'], after: ['No'] }));
    expect(explained.evidence[0].entities).toEqual([{ id: 'o1', name: '1.2.3.4', entity_type: 'IPv4-Addr' }]);
    expectPlainLanguage(explained.text);
  });

  it('explains a split with the entities the merge restores, and says it cannot be reverted', () => {
    const explained = buildProposalExplanation(proposal({
      proposal_kind: 'split',
      recommended_action: 'unmerge',
      subject_ids: ['m'],
      subject_names: ['APT28'],
      curation_evidence: [evidenceItem('merged_entity', { entity_name: 'APT28', source_names: ['Sofacy'] })],
    }), []);
    expect(explained.title.text).toBe('Undo the merge of "APT28"');
    expect(explained.changes[0]).toEqual(expect.objectContaining({ before: ['APT28'], after: ['APT28', 'Sofacy'] }));
    expect(explained.reversible).toBe(false);
    expectPlainLanguage(explained.text);
  });

  it('explains a stale entity with its last activity', () => {
    const explained = buildProposalExplanation(proposal({
      proposal_kind: 'stale',
      recommended_action: 'revoke',
      subject_ids: ['s'],
      subject_names: ['Old campaign'],
      in_ambiguous_band: false,
      confidence_score: 0.5,
      curation_evidence: [evidenceItem('staleness', { last_activity: '2023-02-01T00:00:00.000Z', months: 24 })],
    }), []);
    expect(explained.title.text).toBe('Revoke "Old campaign"');
    expect(explained.evidence[0].message.text).toBe('No update and no new relationship since 2023-02-01 (more than 24 months)');
    expect(explained.why.text).toContain('more than 24 months');
    expect(explained.confidence.level).toBe('low');
    expect(explained.confidence.meaning.text).toBe('Low (50%): the evidence is weak. Check it before accepting.');
    expectPlainLanguage(explained.text);
  });

  it('explains a relationship conflict according to how the platform keeps procedures', () => {
    const base = proposal({
      proposal_kind: 'relationship_conflict',
      recommended_action: 'preserve_procedure',
      action_payload: JSON.stringify({ relationship_id: 'r', previous: { text: 'Uses it over SMB' }, current: { text: 'Uses it over HTTP' } }),
      subject_ids: ['r'],
      subject_names: ['APT28 uses Mimikatz'],
      curation_evidence: [evidenceItem('procedure_conflict', { from_name: 'APT28', to_name: 'Mimikatz' })],
    });
    const kept = buildProposalExplanation(base, [], { relationshipConflictMode: 'procedures_array' });
    expect(kept.title.text).toBe('Keep both procedures of "APT28 uses Mimikatz"');
    expect(kept.changes[0]).toEqual(expect.objectContaining({ before: ['Uses it over HTTP'], after: ['Uses it over SMB', 'Uses it over HTTP'] }));
    const noted = buildProposalExplanation(base, [], { relationshipConflictMode: 'note' });
    expect(noted.changes[0].field.text).toBe('Notes');
    expect(noted.on_accept.text).toContain('note');
    expect(buildProposalExplanation(base, [], { relationshipConflictMode: 'detect_only' }).changes).toEqual([]);
    expectPlainLanguage(kept.text);
  });

  it('explains a field precedence with the value it restores', () => {
    const explained = buildProposalExplanation(proposal({
      proposal_kind: 'field_precedence',
      recommended_action: 'set_field',
      action_payload: JSON.stringify({ element_id: 'x', key: 'description', value: 'Russian actor', overwritten_value: 'Unknown' }),
      subject_ids: ['x'],
      subject_names: ['APT28'],
      curation_evidence: [evidenceItem('field_conflict', { field: 'description' })],
    }), [{ internal_id: 'x', entity_type: 'Intrusion-Set', name: 'APT28' }]);
    expect(explained.title.text).toBe('Restore the description of "APT28"');
    expect(explained.changes[0]).toEqual(expect.objectContaining({ before: ['Unknown'], after: ['Russian actor'] }));
    expect(explained.why.text).toContain('trusted for this field (description, Intrusion Set)');
    expectPlainLanguage(explained.text);
  });

  it('keeps the stored sentence of an evidence recorded without its parameters', () => {
    const explained = buildProposalExplanation(proposal({
      subject_ids: ['a', 'b'],
      subject_names: ['A', 'B'],
      curation_evidence: [{ evidence_type: 'trigram', score: 0.9, weight: 0.6, description: 'Recorded by an earlier version', details: null }],
    }), []);
    expect(explained.evidence[0].message).toEqual({ template: '{description}', values: { description: 'Recorded by an earlier version' }, text: 'Recorded by an earlier version' });
  });

  it('renders the value conventions of the templates', () => {
    expect(renderTemplate('{leftType} {startField} {date} {count}', { leftType: 'Intrusion-Set', startField: 'valid_until', date: '2024-01-02T10:20:00.000Z', count: 3 }))
      .toBe('Intrusion Set Valid until 2024-01-02 10:20 UTC 3');
  });
});
