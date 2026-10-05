import { beforeEach, describe, expect, it, vi } from 'vitest';
import { checkAliasOwnership } from '../../../../src/modules/curation/curation-scan';
import { detectMissingAliases, toCuratedEntity } from '../../../../src/modules/curation/curation-detectors';
import { generateAliasesId } from '../../../../src/schema/identifier';
import type { CurationSettings, ProposalDraft } from '../../../../src/modules/curation/curation-types';

const state = vi.hoisted(() => ({ stored: [] as Array<Record<string, any>> }));

// The graph outside the scanned slice: entities found through the alias identifiers they hold.
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(async (_context: unknown, _user: unknown, ids: string[]) => state.stored
    .filter((entity) => (entity.i_aliases_ids as string[]).some((id) => ids.includes(id)))),
}));

const intrusionSet = (id: string, name: string) => toCuratedEntity({
  internal_id: id,
  standard_id: `intrusion-set--${id}`,
  entity_type: 'Intrusion-Set',
  name,
  aliases: [],
  marking_ids: [],
  organization_ids: [],
});

const storedIntrusionSet = (id: string, name: string) => ({
  internal_id: id,
  standard_id: `intrusion-set--${id}`,
  entity_type: 'Intrusion-Set',
  name,
  aliases: [],
  i_aliases_ids: generateAliasesId([name], { entity_type: 'Intrusion-Set' }),
});

const settings = { curated_entity_types: ['Intrusion-Set', 'Threat-Actor-Group'] } as unknown as CurationSettings;
const proposedAliases = (drafts: ProposalDraft[]) => drafts.flatMap((draft) => (draft.action_payload?.aliases ?? []) as string[]);

describe('alias ownership of a bounded scan', () => {
  const apt28 = intrusionSet('apt28', 'APT28');

  beforeEach(() => {
    state.stored = [];
  });

  it('never proposes an alias that an entity outside the scanned slice holds', async () => {
    const drafts = detectMissingAliases([apt28]);
    expect(proposedAliases(drafts)).toContain('Sofacy');
    state.stored = [storedIntrusionSet('sofacy', 'Sofacy')];
    const checked = await checkAliasOwnership({} as never, settings, [apt28], drafts);
    expect(proposedAliases(checked)).not.toContain('Sofacy');
    expect(proposedAliases(checked)).toContain('Fancy Bear');
    // The evidence describes the aliases the proposal adds, not the ones it dropped.
    checked.forEach((draft) => {
      expect(JSON.parse(draft.evidence[0].details as unknown as string).aliases).toEqual(draft.action_payload?.aliases);
    });
  });

  it('keeps the proposals as they are when no other entity holds their aliases', async () => {
    const merge = { kind: 'merge', subjects: [], action_payload: {} } as unknown as ProposalDraft;
    const drafts = [...detectMissingAliases([apt28]), merge];
    state.stored = [storedIntrusionSet('apt28', 'APT28')];
    expect(await checkAliasOwnership({} as never, settings, [apt28], drafts)).toBe(drafts);
  });
});
