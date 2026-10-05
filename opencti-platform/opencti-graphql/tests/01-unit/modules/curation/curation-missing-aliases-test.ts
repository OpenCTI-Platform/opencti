import { describe, expect, it } from 'vitest';
import { detectMissingAliases, toCuratedEntity } from '../../../../src/modules/curation/curation-detectors';

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
});
