import { describe, expect, it } from 'vitest';
import { entityIdOfMatchEvent, isRequirementMatchEvent, requirementTransitionOfMatchEvent } from '../../../../src/manager/playbookManager/listenRequirementEventsUtils';
import type { StreamDataEvent } from '../../../../src/types/event';
import type { RequirementStreamConfiguration } from '../../../../src/modules/playbook/components/data-stream-requirement-component';
import { ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirementMatch-types';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';

const matchData = (fields: Record<string, unknown>) => ({
  id: 'intelligence-requirement-match--1',
  type: 'intelligence-requirement-match',
  ir_id: 'ir-1',
  match_entity_id: 'entity-1',
  match_status: 'auto',
  match_excluded: false,
  extensions: { [STIX_EXT_OCTI]: { id: 'match-1', type: ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH } },
  ...fields,
});

const event = (type: string, data: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
  scope: 'internal',
  type,
  origin: {},
  message: '',
  version: '4',
  data,
  ...extra,
}) as unknown as StreamDataEvent;

const config = (fields: Partial<RequirementStreamConfiguration> = {}): RequirementStreamConfiguration => ({
  create: true,
  delete: true,
  update: false,
  create_rel: false,
  filters: '',
  requirementFilters: [],
  ...fields,
});

describe('listenRequirementEventsUtils', () => {
  it('recognizes a match event only with the internal scope', () => {
    expect(isRequirementMatchEvent(event('create', matchData({})))).toBe(true);
    expect(isRequirementMatchEvent(event('create', matchData({}), { scope: 'external' }))).toBe(false);
    expect(isRequirementMatchEvent(event('create', { type: 'malware', extensions: { [STIX_EXT_OCTI]: { type: 'Malware' } } }))).toBe(false);
  });

  it('reads an entry on the creation of a match part of the requirement', () => {
    expect(requirementTransitionOfMatchEvent(event('create', matchData({ match_status: 'auto' })))).toBe('enter');
    expect(requirementTransitionOfMatchEvent(event('create', matchData({ match_status: 'proposed' })))).toBe(null);
    expect(requirementTransitionOfMatchEvent(event('create', matchData({ match_status: 'accepted', match_excluded: true })))).toBe(null);
  });

  it('reads an exit on the deletion of a match that was part of the requirement', () => {
    expect(requirementTransitionOfMatchEvent(event('delete', matchData({ match_status: 'accepted' })))).toBe('leave');
    expect(requirementTransitionOfMatchEvent(event('delete', matchData({ match_status: 'rejected' })))).toBe(null);
  });

  it('reads an entry or an exit on an update that changes the status', () => {
    const accepted = event('update', matchData({ match_status: 'accepted' }), {
      context: { patch: [], reverse_patch: [{ op: 'replace', path: '/match_status', value: 'proposed' }], changes: [] },
    });
    expect(requirementTransitionOfMatchEvent(accepted)).toBe('enter');
    const removed = event('update', matchData({ match_status: 'removed' }), {
      context: { patch: [], reverse_patch: [{ op: 'replace', path: '/match_status', value: 'auto' }], changes: [] },
    });
    expect(requirementTransitionOfMatchEvent(removed)).toBe('leave');
    const scoreOnly = event('update', matchData({ match_score: 80 }), {
      context: { patch: [], reverse_patch: [{ op: 'replace', path: '/match_score', value: 50 }], changes: [] },
    });
    expect(requirementTransitionOfMatchEvent(scoreOnly)).toBe(null);
    const noPatch = event('update', matchData({}), { context: { patch: [], changes: [] } });
    expect(requirementTransitionOfMatchEvent(noPatch)).toBe(null);
  });

  it('returns the entity of the match for the toggles and requirements selected', () => {
    const entered = event('create', matchData({ match_status: 'auto' }));
    const left = event('delete', matchData({ match_status: 'auto' }));
    expect(entityIdOfMatchEvent(entered, config())).toBe('entity-1');
    expect(entityIdOfMatchEvent(entered, config({ create: false }))).toBe(null);
    expect(entityIdOfMatchEvent(left, config())).toBe('entity-1');
    expect(entityIdOfMatchEvent(left, config({ delete: false }))).toBe(null);
    expect(entityIdOfMatchEvent(entered, config({ requirementFilters: [{ value: 'ir-1' }] }))).toBe('entity-1');
    expect(entityIdOfMatchEvent(entered, config({ requirementFilters: [{ value: 'ir-2' }] }))).toBe(null);
  });
});
