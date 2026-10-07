import { describe, expect, it, vi } from 'vitest';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { getEntitiesMapFromCache } from '../../../../src/database/cache';
import { buildHuntRunMessage } from '../../../../src/modules/hunt/hunt-dispatch';
import { RELATION_HUNT_SOURCES, RELATION_HUNT_TARGETS, RELATION_HUNT_TECHNIQUES } from '../../../../src/modules/hunt/hunt-types';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntitiesMapFromCache: vi.fn(),
}));

const markings = new Map([
  ['marking-green', { internal_id: 'marking-green', standard_id: 'marking-definition--green', definition_type: 'TLP', x_opencti_order: 2 }],
  ['marking-red', { internal_id: 'marking-red', standard_id: 'marking-definition--red', definition_type: 'TLP', x_opencti_order: 4 }],
]);
const indicator = (id: string, marking: string) => ({
  internal_id: id,
  standard_id: `indicator--${id}`,
  entity_type: 'Indicator',
  name: `Indicator ${id}`,
  pattern_type: 'stix',
  pattern: `[ipv4-addr:value = '198.51.100.${id.length}']`,
  [RELATION_OBJECT_MARKING]: [marking],
});
const reference = (id: string, entityType: string, references: Record<string, string[]>) => ({
  internal_id: id,
  standard_id: `${entityType.toLowerCase()}--${id}`,
  entity_type: entityType,
  name: `${entityType} ${id}`,
  ...references,
});
const elements = new Map<string, unknown>([
  ['readable', indicator('readable', 'marking-green')],
  ['restricted', indicator('restricted', 'marking-red')],
  ['technique-readable', reference('technique-readable', 'Attack-Pattern', {})],
  ['technique-restricted', reference('technique-restricted', 'Attack-Pattern', { [RELATION_OBJECT_MARKING]: ['marking-red'] })],
  ['target-readable', reference('target-readable', 'Intrusion-Set', { [RELATION_OBJECT_MARKING]: ['marking-green'] })],
  ['target-restricted', reference('target-restricted', 'Intrusion-Set', { [RELATION_OBJECT_MARKING]: ['marking-red'] })],
  ['target-organization', reference('target-organization', 'Malware', { [RELATION_GRANTED_TO]: ['organization-1'] })],
  ['author-restricted', reference('author-restricted', 'Organization', { [RELATION_OBJECT_MARKING]: ['marking-red'] })],
  ['organization-1', reference('organization-1', 'Organization', {})],
  ...Array.from(markings.entries()),
]);

describe('Hunt run message', () => {
  it('should neither describe nor sight an indicator more restricted than the hunt', async () => {
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(markings as never);
    vi.mocked(findByIds).mockImplementation(async (_context, _user, ids) => ids.map((id) => elements.get(id)).filter((element) => !!element) as never);
    const hunt = {
      internal_id: 'hunt-1',
      standard_id: 'hunt--1',
      name: 'Restricted sources',
      hunt_type: 'telemetry',
      native_queries: [],
      escalation_threshold: 1,
      [RELATION_HUNT_SOURCES]: ['readable', 'restricted'],
      [RELATION_OBJECT_MARKING]: ['marking-green'],
    };
    const run = { internal_id: 'run-1', attempt: 1, hunt_run_trigger: 'manual', hunt_run_mode: 'execute' };
    const message = await buildHuntRunMessage(testContext, run as never, hunt as never, { hunt_platform: 'splunk' } as never, null, 'work-1');
    expect(message.event.hunt.indicators.map((element) => element.standard_id)).toEqual(['indicator--readable']);
    expect(message.event.hunt.object_marking_refs).toEqual(['marking-definition--green']);
    expect(message.event.hunt.granted_refs).toEqual([]);
  });

  it('should give the connector the markings and organizations of the run for its evidence', async () => {
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(markings as never);
    vi.mocked(findByIds).mockImplementation(async (_context, _user, ids) => ids.map((id) => elements.get(id)).filter((element) => !!element) as never);
    const hunt = {
      internal_id: 'hunt-3',
      standard_id: 'hunt--3',
      name: 'Restricted platform',
      hunt_type: 'telemetry',
      native_queries: [],
      escalation_threshold: 1,
      [RELATION_OBJECT_MARKING]: ['marking-green'],
    };
    // The run carries the markings of the hunt and of its security platform, and the organizations both share
    const run = {
      internal_id: 'run-3',
      attempt: 1,
      hunt_run_trigger: 'manual',
      hunt_run_mode: 'execute',
      [RELATION_OBJECT_MARKING]: ['marking-green', 'marking-red'],
      [RELATION_GRANTED_TO]: ['organization-1'],
    };
    const message = await buildHuntRunMessage(testContext, run as never, hunt as never, { hunt_platform: 'splunk' } as never, null, 'work-3');
    expect(message.event.hunt.object_marking_refs).toEqual(['marking-definition--green', 'marking-definition--red']);
    expect(message.event.hunt.granted_refs).toEqual(['organization--organization-1']);
  });

  it('should name to the connector no technique, target or author more restricted than the hunt', async () => {
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(markings as never);
    vi.mocked(findByIds).mockImplementation(async (_context, _user, ids) => ids.map((id) => elements.get(id)).filter((element) => !!element) as never);
    const hunt = {
      internal_id: 'hunt-2',
      standard_id: 'hunt--2',
      name: 'Restricted references',
      hunt_type: 'telemetry',
      native_queries: [],
      escalation_threshold: 1,
      [RELATION_HUNT_TECHNIQUES]: ['technique-readable', 'technique-restricted'],
      [RELATION_HUNT_TARGETS]: ['target-readable', 'target-restricted', 'target-organization'],
      [RELATION_CREATED_BY]: 'author-restricted',
      [RELATION_OBJECT_MARKING]: ['marking-green'],
    };
    const run = { internal_id: 'run-2', attempt: 1, hunt_run_trigger: 'manual', hunt_run_mode: 'execute' };
    const message = await buildHuntRunMessage(testContext, run as never, hunt as never, { hunt_platform: 'splunk' } as never, null, 'work-2');
    expect(message.event.hunt.techniques.map((element) => element.standard_id)).toEqual(['attack-pattern--technique-readable']);
    // A hunt shared with no organization is read by the platform organization only, which reads every organization
    expect(message.event.hunt.targets.map((element) => element.standard_id)).toEqual(['intrusion-set--target-readable', 'malware--target-organization']);
    expect(message.event.hunt.created_by_ref).toBeNull();
    const sharedHunt = { ...hunt, [RELATION_GRANTED_TO]: ['organization-1'] };
    const shared = await buildHuntRunMessage(testContext, run as never, sharedHunt as never, { hunt_platform: 'splunk' } as never, null, 'work-2');
    expect(shared.event.hunt.targets.map((element) => element.standard_id)).toEqual(['malware--target-organization']);
  });
});
