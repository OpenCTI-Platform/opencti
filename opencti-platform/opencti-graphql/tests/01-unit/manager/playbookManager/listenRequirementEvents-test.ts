import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SseEvent, StreamDataEvent } from '../../../../src/types/event';
import type { NodeDefinition, BasicStoreEntityPlaybook } from '../../../../src/modules/playbook/playbook-types';
import type { RequirementStreamConfiguration } from '../../../../src/modules/playbook/components/data-stream-requirement-component';
import type { AuthContext } from '../../../../src/types/user';
import { ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirementMatch-types';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';

const mocks = vi.hoisted(() => ({
  stixLoadById: vi.fn(),
  fullEntitiesList: vi.fn(),
  isStixMatchFilterGroup: vi.fn(),
  playbookExecutor: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', () => ({ stixLoadById: mocks.stixLoadById }));
vi.mock('../../../../src/database/middleware-loader', () => ({ fullEntitiesList: mocks.fullEntitiesList }));
vi.mock('../../../../src/utils/filtering/filtering-stix/stix-filtering', () => ({ isStixMatchFilterGroup: mocks.isStixMatchFilterGroup }));
vi.mock('../../../../src/manager/playbookManager/playbookExecutor', () => ({ playbookExecutor: mocks.playbookExecutor }));
vi.mock('../../../../src/modules/playbook/playbook-components', () => ({ PLAYBOOK_COMPONENTS: { 'component-1': { id: 'component-1' } } }));

const {
  entitiesInSelectedRequirements,
  listenRequirementEvents,
  previousMatchOfUpdate,
  resolveRequirementEventEntity,
} = await import('../../../../src/manager/playbookManager/listenRequirementEventsUtils');

const context = {} as AuthContext;

const matchData = (fields: Record<string, unknown> = {}) => ({
  id: 'intelligence-requirement-match--1',
  type: 'intelligence-requirement-match',
  ir_id: 'ir-1',
  match_entity_id: 'entity-1',
  match_status: 'auto',
  match_excluded: false,
  extensions: { [STIX_EXT_OCTI]: { id: 'match-1', type: ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH } },
  ...fields,
});

const entityData = { id: 'malware--1', type: 'malware', extensions: { [STIX_EXT_OCTI]: { id: 'entity-1', type: 'Malware' } } };

const relationData = {
  id: 'relationship--1',
  type: 'relationship',
  relationship_type: 'uses',
  source_ref: 'malware--1',
  target_ref: 'attack-pattern--1',
  extensions: { [STIX_EXT_OCTI]: { id: 'rel-1', type: 'uses', source_ref: 'entity-1', target_ref: 'entity-2' } },
};

const event = (type: string, data: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
  scope: 'external',
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
  update: true,
  create_rel: true,
  filters: '',
  requirementFilters: [],
  ...fields,
});

const storedMatch = (entityId: string, fields: Record<string, unknown> = {}) => ({ match_entity_id: entityId, match_status: 'auto', match_excluded: false, ...fields });

describe('listenRequirementEventsUtils with the store', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rebuilds the previous match of an update, undefined without a usable reverse patch', () => {
    const update = event('update', matchData({ match_status: 'accepted' }), {
      context: { reverse_patch: [{ op: 'replace', path: '/match_status', value: 'proposed' }] },
    });
    expect(previousMatchOfUpdate(update as never)?.match_status).toBe('proposed');
    expect(previousMatchOfUpdate(event('update', matchData(), { context: {} }) as never)).toBeUndefined();
    const broken = event('update', matchData(), { context: { reverse_patch: [{ op: 'test', path: '/match_status', value: 'nope' }] } });
    expect(previousMatchOfUpdate(broken as never)).toBeUndefined();
  });

  it('reads the entities part of the selected requirements from the stored matches', async () => {
    expect((await entitiesInSelectedRequirements(context, ['', undefined as unknown as string], [])).size).toBe(0);
    expect(mocks.fullEntitiesList).not.toHaveBeenCalled();
    mocks.fullEntitiesList.mockResolvedValueOnce([storedMatch('entity-1'), storedMatch('entity-2', { match_status: 'rejected' })]);
    const inRequirement = await entitiesInSelectedRequirements(context, ['entity-1', 'entity-2'], [{ value: 'ir-1' }]);
    expect(Array.from(inRequirement)).toEqual(['entity-1']);
    const { filters } = mocks.fullEntitiesList.mock.calls[0][3];
    expect(JSON.stringify(filters)).toContain('match_entity_id');
    expect(JSON.stringify(filters)).toContain('ir_id');
  });

  it('resolves the entity that enters a requirement, and ignores other match events', async () => {
    mocks.stixLoadById.mockResolvedValueOnce(entityData);
    const entered = event('create', matchData(), { scope: 'internal' });
    expect(await resolveRequirementEventEntity(context, entered, config())).toEqual(entityData);
    expect(mocks.stixLoadById.mock.calls[0][2]).toBe('entity-1');
    const proposed = event('create', matchData({ match_status: 'proposed' }), { scope: 'internal' });
    expect(await resolveRequirementEventEntity(context, proposed, config())).toBeUndefined();
  });

  it('resolves an updated entity only when it is part of a selected requirement', async () => {
    const updated = event('update', entityData);
    mocks.fullEntitiesList.mockResolvedValueOnce([storedMatch('entity-1')]);
    expect(await resolveRequirementEventEntity(context, updated, config())).toEqual(entityData);
    mocks.fullEntitiesList.mockResolvedValueOnce([]);
    expect(await resolveRequirementEventEntity(context, updated, config())).toBeUndefined();
    const noId = event('update', { id: 'malware--2', type: 'malware', extensions: { [STIX_EXT_OCTI]: {} } });
    expect(await resolveRequirementEventEntity(context, noId, config())).toBeUndefined();
    expect(await resolveRequirementEventEntity(context, updated, config({ update: false }))).toBeUndefined();
  });

  it('resolves the other end of a relationship linked to an entity part of a requirement', async () => {
    const created = event('create', relationData);
    mocks.fullEntitiesList.mockResolvedValueOnce([storedMatch('entity-1')]);
    mocks.stixLoadById.mockResolvedValueOnce({ id: 'attack-pattern--1' });
    expect(await resolveRequirementEventEntity(context, created, config())).toEqual({ id: 'attack-pattern--1' });
    expect(mocks.stixLoadById.mock.calls[0][2]).toBe('attack-pattern--1');
    mocks.fullEntitiesList.mockResolvedValueOnce([storedMatch('entity-2')]);
    mocks.stixLoadById.mockResolvedValueOnce({ id: 'malware--1' });
    expect(await resolveRequirementEventEntity(context, created, config())).toEqual({ id: 'malware--1' });
    expect(mocks.stixLoadById.mock.calls[1][2]).toBe('malware--1');
    mocks.fullEntitiesList.mockResolvedValueOnce([]);
    expect(await resolveRequirementEventEntity(context, created, config())).toBeUndefined();
    expect(await resolveRequirementEventEntity(context, created, config({ create_rel: false }))).toBeUndefined();
  });

  describe('listenRequirementEvents', () => {
    const instance = (configuration: Partial<RequirementStreamConfiguration>) => ({
      id: 'instance-1',
      component_id: 'component-1',
      configuration: JSON.stringify(config(configuration)),
    }) as unknown as NodeDefinition;
    const playbook = { id: 'playbook-1', playbook_definition: JSON.stringify({ nodes: [], links: [] }) } as unknown as BasicStoreEntityPlaybook;
    const sse = (data: StreamDataEvent) => ({ id: 'event-1', event: 'create', data }) as unknown as SseEvent<StreamDataEvent>;

    it('runs the playbook with a bundle holding the entity of interest', async () => {
      mocks.stixLoadById.mockResolvedValueOnce(entityData);
      mocks.isStixMatchFilterGroup.mockResolvedValueOnce(true);
      await listenRequirementEvents(context, sse(event('create', matchData(), { scope: 'internal' })), instance({ filters: '{"mode":"and","filters":[],"filterGroups":[]}' }), playbook);
      expect(mocks.playbookExecutor).toHaveBeenCalledTimes(1);
      const args = mocks.playbookExecutor.mock.calls[0][0];
      expect(args.bundle.objects).toEqual([entityData]);
      expect(args.dataInstanceId).toBe('malware--1');
      expect(args.nextStep.component).toEqual({ id: 'component-1' });
    });

    it('stops when the entity does not match the source filters, or when nothing is resolved', async () => {
      mocks.stixLoadById.mockResolvedValueOnce(entityData);
      mocks.isStixMatchFilterGroup.mockResolvedValueOnce(false);
      await listenRequirementEvents(context, sse(event('create', matchData(), { scope: 'internal' })), instance({ filters: 'not json' }), playbook);
      expect(mocks.isStixMatchFilterGroup.mock.calls[0][3]).toBeUndefined();
      await listenRequirementEvents(context, sse(event('create', matchData({ match_status: 'proposed' }), { scope: 'internal' })), instance({}), playbook);
      expect(mocks.playbookExecutor).not.toHaveBeenCalled();
    });

    it('ignores an event type the configuration does not listen to', async () => {
      await listenRequirementEvents(context, sse(event('delete', entityData)), instance({ delete: false }), playbook);
      expect(mocks.fullEntitiesList).not.toHaveBeenCalled();
      expect(mocks.playbookExecutor).not.toHaveBeenCalled();
    });
  });
});
