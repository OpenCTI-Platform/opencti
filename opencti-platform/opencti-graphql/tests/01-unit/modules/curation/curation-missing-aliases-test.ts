import { describe, expect, it } from 'vitest';
import { detectMissingAliases, toCuratedEntity } from '../../../../src/modules/curation/curation-detectors';
import { supersededAliasProposals } from '../../../../src/modules/curation/curation-proposals';

const intrusionSet = (id: string, name: string, aliases: string[] = []) => toCuratedEntity({
  internal_id: id,
  standard_id: `intrusion-set--${id}`,
  entity_type: 'Intrusion-Set',
  name,
  aliases,
  marking_ids: [],
  organization_ids: [],
});

const proposedAliases = (drafts: ReturnType<typeof detectMissingAliases>) => drafts.flatMap((draft) => (draft.action_payload?.aliases ?? []) as string[]);

describe('missing aliases detection', () => {
  const apt28 = intrusionSet('apt28', 'APT28');
  const fancyBear = intrusionSet('fancy-bear', 'Fancy Bear');

  it('proposes the taxonomy names an entity does not carry, except the names of other entities', () => {
    const drafts = detectMissingAliases([apt28, fancyBear]);
    const forApt28 = drafts.filter((draft) => draft.target_id === 'apt28');
    expect(proposedAliases(forApt28)).toContain('Sofacy');
    expect(proposedAliases(forApt28)).not.toContain('Fancy Bear');
  });

  it('keeps the names of every candidate out of the proposals of the focused entities', () => {
    const drafts = detectMissingAliases([apt28, fancyBear], new Set(['apt28']));
    expect(drafts.every((draft) => draft.target_id === 'apt28')).toBe(true);
    expect(proposedAliases(drafts)).toContain('Sofacy');
    expect(proposedAliases(drafts)).not.toContain('Fancy Bear');
  });

  it('raises one proposal per entity, citing every catalogue that lists the names', () => {
    const drafts = detectMissingAliases([apt28]);
    expect(drafts).toHaveLength(1);
    const [draft] = drafts;
    const sources = draft.evidence.map((item) => JSON.parse(item.details as string).source);
    expect(sources).toEqual(['mitre', 'misp-threat-actor']);
    const aliases = proposedAliases(drafts);
    // Each name once, in the spelling of the most reliable catalogue.
    expect(new Set(aliases.map((alias) => alias.toLowerCase())).size).toBe(aliases.length);
    expect(aliases).toContain('Fancy Bear');
    expect(aliases).not.toContain('FANCY BEAR');
    const listedByMitre = JSON.parse(draft.evidence[0].details as string);
    expect(listedByMitre.matched_name).toBe('APT28');
    expect(listedByMitre.aliases).toContain('Sofacy');
  });

  it('never proposes a catalogue identifier as an alias', () => {
    expect(proposedAliases(detectMissingAliases([apt28]))).not.toContain('G0007');
  });

  it('replaces the older open alias proposals of the same entity, and only those', () => {
    const proposal = (id: string, fingerprint: string, subjectIds: string[], overrides: Record<string, string> = {}) => ({
      internal_id: id,
      proposal_kind: 'alias',
      proposal_status: 'open',
      proposal_fingerprint: fingerprint,
      subject_ids: subjectIds,
      ...overrides,
    }) as never;
    const current = proposal('new', 'f-new', ['apt28']);
    const open = [
      current,
      proposal('per-catalogue-mitre', 'f-mitre', ['apt28']),
      proposal('per-catalogue-misp', 'f-misp', ['apt28']),
      proposal('other-entity', 'f-other', ['apt29']),
      proposal('decided', 'f-decided', ['apt28'], { proposal_status: 'accepted' }),
      proposal('being-applied', 'f-started', ['apt28'], { application_started_at: '2026-10-06T16:00:00.000Z' }),
      proposal('merge', 'f-merge', ['apt28'], { proposal_kind: 'merge' }),
    ];
    expect(supersededAliasProposals(open, current).map((p) => (p as { internal_id: string }).internal_id)).toEqual(['per-catalogue-mitre', 'per-catalogue-misp']);
  });

  it('never proposes a name that a catalogue also gives to another actor', () => {
    // The MISP galaxy lists "Grizzly Steppe" for both APT28 and APT29.
    const aliases = proposedAliases(detectMissingAliases([apt28]));
    expect(aliases).not.toContain('Grizzly Steppe');
    expect(aliases).toContain('Forest Blizzard');
  });
});
