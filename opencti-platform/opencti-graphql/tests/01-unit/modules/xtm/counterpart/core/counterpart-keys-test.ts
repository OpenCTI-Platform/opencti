import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  internalFindByIds: vi.fn(),
  fullRelationsList: vi.fn(),
}));

// The objects and their external references are read from the database; the tests give them.
vi.mock('../../../../../../src/database/middleware-loader', () => ({
  internalFindByIds: mocks.internalFindByIds,
  fullRelationsList: mocks.fullRelationsList,
}));

import { counterpartKeyOf, counterpartKeysOf, counterpartKindOf } from '../../../../../../src/modules/xtm/counterpart/core/counterpart-keys';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_IDENTITY_SYSTEM, ENTITY_TYPE_INCIDENT, ENTITY_TYPE_INTRUSION_SET } from '../../../../../../src/schema/stixDomainObject';
import { ENTITY_HOSTNAME, ENTITY_IPV4_ADDR } from '../../../../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_VULNERABILITY } from '../../../../../../src/modules/vulnerability/vulnerability-types';

const context = {} as any;
const user = {} as any;
// Lower-cases every key and drops an empty one, so the tests see what the normaliser is given.
const normalise = (_kind: string, key: string | null | undefined) => (key && key.trim() ? key.trim().toLowerCase() : null);

describe('XTM counterpart keys: kind and key of an object', () => {
  it('maps each entity type to the kind it is matched as', () => {
    expect(counterpartKindOf(ENTITY_TYPE_IDENTITY_SYSTEM)).toBe('ASSET');
    expect(counterpartKindOf(ENTITY_HOSTNAME)).toBe('ASSET');
    expect(counterpartKindOf(ENTITY_IPV4_ADDR)).toBe('ASSET');
    expect(counterpartKindOf(ENTITY_TYPE_ATTACK_PATTERN)).toBe('ATTACK_PATTERN');
    expect(counterpartKindOf(ENTITY_TYPE_VULNERABILITY)).toBe('VULNERABILITY');
    expect(counterpartKindOf(ENTITY_TYPE_INTRUSION_SET)).toBe('THREAT');
    expect(counterpartKindOf(ENTITY_TYPE_INCIDENT)).toBe('ALERT');
    expect(counterpartKindOf('Note')).toBeNull();
  });

  it('reads the key each kind is matched on', () => {
    expect(counterpartKeyOf('ASSET', { entity_type: ENTITY_TYPE_IDENTITY_SYSTEM, name: 'web-01' })).toBe('web-01');
    expect(counterpartKeyOf('ASSET', { entity_type: ENTITY_IPV4_ADDR, value: '10.0.0.1' })).toBe('10.0.0.1');
    expect(counterpartKeyOf('ATTACK_PATTERN', { x_mitre_id: 'T1059' })).toBe('T1059');
    expect(counterpartKeyOf('ATTACK_PATTERN', {})).toBeNull();
    expect(counterpartKeyOf('VULNERABILITY', { name: 'CVE-2024-3400' })).toBe('CVE-2024-3400');
    expect(counterpartKeyOf('VULNERABILITY', {})).toBeNull();
    expect(counterpartKeyOf('THREAT', { standard_id: 'intrusion-set--1' })).toBe('intrusion-set--1');
    expect(counterpartKeyOf('THREAT', {})).toBeNull();
    expect(counterpartKeyOf('ALERT', { name: 'any' })).toBeNull();
  });
});

describe('XTM counterpart keys: read on the server under the caller rights', () => {
  beforeEach(() => {
    mocks.internalFindByIds.mockReset();
    mocks.fullRelationsList.mockReset();
  });

  it('answers nothing and reads nothing for no usable id', async () => {
    expect(await counterpartKeysOf(context, user, ['', null as any], normalise)).toEqual([]);
    expect(mocks.internalFindByIds).not.toHaveBeenCalled();
  });

  it('keys each readable object by the id the caller gave, and drops unreadable, unmatched or keyless ones', async () => {
    mocks.internalFindByIds.mockResolvedValueOnce([
      { internal_id: 'sys-1', standard_id: 'system--1', entity_type: ENTITY_TYPE_IDENTITY_SYSTEM, name: ' WEB-01 ' },
      {
        internal_id: 'ap-1',
        standard_id: 'attack-pattern--1',
        entity_type: ENTITY_TYPE_ATTACK_PATTERN,
        x_mitre_id: 'T1059',
        x_opencti_stix_ids: ['attack-pattern--old'],
      },
      { internal_id: 'vuln-1', standard_id: 'vulnerability--1', entity_type: ENTITY_TYPE_VULNERABILITY },
      { internal_id: 'note-1', standard_id: 'note--1', entity_type: 'Note' },
    ]);
    const sources = await counterpartKeysOf(context, user, ['sys-1', 'attack-pattern--old', 'vuln-1', 'note-1', 'hidden-1', 'sys-1'], normalise);
    expect(sources).toEqual([
      { id: 'sys-1', kind: 'ASSET', keys: ['web-01'] },
      { id: 'attack-pattern--old', kind: 'ATTACK_PATTERN', keys: ['t1059'] },
    ]);
    expect(mocks.internalFindByIds).toHaveBeenCalledWith(context, user, ['sys-1', 'attack-pattern--old', 'vuln-1', 'note-1', 'hidden-1']);
    expect(mocks.fullRelationsList).not.toHaveBeenCalled();
  });

  it('matches an alert on the URLs of its external references, deduplicated and capped at 20', async () => {
    const refs = Array.from({ length: 25 }, (_, i) => ({ internal_id: `ref-${i}`, url: `https://edr.example.com/alerts/${i}` }));
    mocks.internalFindByIds
      .mockResolvedValueOnce([
        { internal_id: 'inc-1', standard_id: 'incident--1', entity_type: ENTITY_TYPE_INCIDENT },
        { internal_id: 'inc-2', standard_id: 'incident--2', entity_type: ENTITY_TYPE_INCIDENT },
      ])
      .mockResolvedValueOnce([...refs, { internal_id: 'ref-nourl' }]);
    mocks.fullRelationsList.mockResolvedValueOnce([
      ...refs.map((ref) => ({ fromId: 'inc-1', toId: ref.internal_id })),
      { fromId: 'inc-2', toId: 'ref-nourl' },
    ]);
    const sources = await counterpartKeysOf(context, user, ['incident--1', 'inc-2'], normalise);
    expect(sources).toHaveLength(1);
    expect(sources[0].id).toBe('incident--1');
    expect(sources[0].kind).toBe('ALERT');
    expect(sources[0].keys).toHaveLength(20);
    expect(sources[0].keys[0]).toBe('https://edr.example.com/alerts/0');
    expect(mocks.fullRelationsList.mock.calls[0][3]).toMatchObject({ fromId: ['inc-1', 'inc-2'] });
  });

  it('reads no reference when the alerts carry no external reference', async () => {
    mocks.internalFindByIds.mockResolvedValueOnce([{ internal_id: 'inc-1', standard_id: 'incident--1', entity_type: ENTITY_TYPE_INCIDENT }]);
    mocks.fullRelationsList.mockResolvedValueOnce([]);
    expect(await counterpartKeysOf(context, user, ['inc-1'], normalise)).toEqual([]);
    expect(mocks.internalFindByIds).toHaveBeenCalledTimes(1);
  });
});
