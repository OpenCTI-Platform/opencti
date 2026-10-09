import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { pick } from 'ramda';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import activityManager, { buildActivityHistoryElements, getLiveActivityNotifications } from '../../../src/manager/activityManager';
import { INDEX_HISTORY, READ_INDEX_HISTORY } from '../../../src/database/utils';
import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY } from '../../../src/schema/internalObject';
import type { ActivityStreamEvent, SseEvent } from '../../../src/types/event';
import { type ActionHandler, registerUserActionListener, type UserAction } from '../../../src/listener/UserActionListener';
import { askEntityExport, askListExport, EXPORT_CONNECTOR_ONLY_FIELDS } from '../../../src/domain/stix';
import { storeLoadById } from '../../../src/database/middleware-loader';
import * as connectorDomain from '../../../src/domain/connector';
import * as workDomain from '../../../src/domain/work';
import * as rabbitmq from '../../../src/database/rabbitmq';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { RELATION_OBJECT_MARKING } from '../../../src/schema/stixRefRelationship';
import { elIndexElements, elRawDeleteByQuery, elRawGet } from '../../../src/database/engine';
import { SYSTEM_USER } from '../../../src/utils/access';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import { MARKING_TLP_CLEAR, MARKING_TLP_GREEN } from '../../../src/schema/identifier';
import type { BasicStoreEntity, StoreMarkingDefinition } from '../../../src/types/store';

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

const TEST_USER_ID = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';
const TEST_GROUP_ID = '9c746e48-28fd-432a-abd7-d7593eb310c4';
// Millisecond unix timestamp used as event id prefix
const EVENT_TIMESTAMP = '1731595374948';

const buildSseEvent = (
  id: string,
  overrides: Partial<ActivityStreamEvent> = {},
): SseEvent<ActivityStreamEvent> => ({
  id,
  event: 'authentication',
  data: {
    version: '4',
    type: 'authentication',
    event_access: 'extended',
    prevent_indexing: false,
    event_scope: 'login',
    message: 'successfully logged in',
    status: 'success',
    origin: {
      user_id: TEST_USER_ID,
      group_ids: [TEST_GROUP_ID],
      organization_ids: [],
      user_metadata: {},
    },
    data: {},
    ...overrides,
  },
});

// -------------------------------------------------------------------
// activityManager.status()
// -------------------------------------------------------------------

describe('Activity manager - status', () => {
  it('should return a status object with the correct shape', () => {
    const status = activityManager.status();
    expect(status.id).toBe('ACTIVITY_MANAGER');
    expect(typeof status.enable).toBe('boolean');
    expect(typeof status.running).toBe('boolean');
  });

  it('should not be running before start', () => {
    const status = activityManager.status();
    expect(status.running).toBe(false);
  });
});

// -------------------------------------------------------------------
// activityManager.shutdown()
// -------------------------------------------------------------------

describe('Activity manager - shutdown', () => {
  it('should return true on shutdown', async () => {
    const result = await activityManager.shutdown();
    expect(result).toBe(true);
  });
});

// -------------------------------------------------------------------
// getLiveActivityNotifications()
// -------------------------------------------------------------------

describe('Activity manager - getLiveActivityNotifications', () => {
  it('should return an array', async () => {
    const notifications = await getLiveActivityNotifications(testContext);
    expect(Array.isArray(notifications)).toBe(true);
  });

  it('should only contain live activity triggers', async () => {
    const notifications = await getLiveActivityNotifications(testContext);
    for (const notif of notifications) {
      expect(notif.trigger.trigger_type).toBe('live');
      expect(notif.trigger.trigger_scope).toBe('activity');
    }
  });
});

// -------------------------------------------------------------------
// buildActivityHistoryElements()
// -------------------------------------------------------------------

describe('Activity manager - buildActivityHistoryElements', () => {
  it('should return an empty array when given no events', async () => {
    const elements = await buildActivityHistoryElements(testContext, []);
    expect(elements).toHaveLength(0);
  });

  it('should exclude events with prevent_indexing=true', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`, { prevent_indexing: true });
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements).toHaveLength(0);
  });

  it('should include events with prevent_indexing=false', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`, { prevent_indexing: false });
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements).toHaveLength(1);
  });

  it('should set entity_type to ENTITY_TYPE_ACTIVITY for administration events', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`, { event_access: 'administration' });
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0].entity_type).toBe(ENTITY_TYPE_ACTIVITY);
  });

  it('should set entity_type to ENTITY_TYPE_HISTORY for extended events', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`, { event_access: 'extended' });
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0].entity_type).toBe(ENTITY_TYPE_HISTORY);
  });

  it('should index elements into INDEX_HISTORY', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`);
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0]._index).toBe(INDEX_HISTORY);
  });

  it('should set internal_id from the SSE event id', async () => {
    const eventId = `${EVENT_TIMESTAMP}-0`;
    const event = buildSseEvent(eventId);
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0].internal_id).toBe(eventId);
  });

  it('should set user_id from origin', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`);
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0].user_id).toBe(TEST_USER_ID);
  });

  it('should set group_ids from origin', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`);
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0].group_ids).toEqual([TEST_GROUP_ID]);
  });

  it('should default group_ids to empty array when not provided in origin', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`);
    event.data.origin = { user_id: TEST_USER_ID };
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0].group_ids).toEqual([]);
  });

  it('should set organization_ids from origin', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`);
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0].organization_ids).toEqual([]);
  });

  it('should set event_scope from event data', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`, { event_scope: 'login' });
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0].event_scope).toBe('login');
  });

  it('should set event_status from event data', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`, { status: 'error' });
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0].event_status).toBe('error');
  });

  it('should correctly process multiple events and filter prevent_indexing', async () => {
    const events = [
      buildSseEvent(`${EVENT_TIMESTAMP}-0`, { event_access: 'administration', prevent_indexing: false }),
      buildSseEvent(`${EVENT_TIMESTAMP}-1`, { event_access: 'extended', prevent_indexing: false }),
      buildSseEvent(`${EVENT_TIMESTAMP}-2`, { prevent_indexing: true }),
    ];
    const elements = await buildActivityHistoryElements(testContext, events);
    expect(elements).toHaveLength(2);
    expect(elements[0].entity_type).toBe(ENTITY_TYPE_ACTIVITY);
    expect(elements[1].entity_type).toBe(ENTITY_TYPE_HISTORY);
  });

  it('should set rel_object-marking.internal_id from event data', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`);
    event.data.data = { object_marking_refs_ids: ['marking-id-1', 'marking-id-2'] };
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0]['rel_object-marking.internal_id']).toEqual(['marking-id-1', 'marking-id-2']);
  });

  it('should set rel_granted.internal_id from event data', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`);
    event.data.data = { granted_refs_ids: ['org-id-1'] };
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0]['rel_granted.internal_id']).toEqual(['org-id-1']);
  });

  it('should include the message in context_data', async () => {
    const event = buildSseEvent(`${EVENT_TIMESTAMP}-0`, { message: 'user logged in successfully' });
    const elements = await buildActivityHistoryElements(testContext, [event]);
    expect(elements[0].context_data.message).toBe('user logged in successfully');
  });
});

// -------------------------------------------------------------------
// Export events indexing
// -------------------------------------------------------------------

describe('Activity manager - export events indexing', () => {
  const REPORT_ID = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
  const EXPORT_FORMAT = 'application/pdf';
  const EXPORT_CONNECTOR = { id: 'export-connector-test', internal_id: 'export-connector-test', name: 'Export connector test' };
  const SHARED_EXPORT_KEYS = ['format', 'export_type', 'entity_id', 'entity_name', 'entity_type'];
  const CONCURRENT_EXPORTS = 5;
  type ConnectorMessage = { event: Record<string, unknown> };
  const exportActions: UserAction[] = [];
  const connectorMessages: ConnectorMessage[] = [];
  let exportListener: ActionHandler;
  let eventIds: string[] = [];
  let report: BasicStoreEntity;
  let tlpGreen: StoreMarkingDefinition;
  let tlpClear: StoreMarkingDefinition;
  let exportUser: typeof ADMIN_USER;

  const leakedKeys = (value: unknown, leaked: string[] = []): string[] => {
    if (Array.isArray(value)) {
      value.forEach((item) => leakedKeys(item, leaked));
    } else if (value && typeof value === 'object') {
      for (const [key, nested] of Object.entries(value)) {
        if (EXPORT_CONNECTOR_ONLY_FIELDS.includes(key)) leaked.push(key);
        leakedKeys(nested, leaked);
      }
    }
    return leaked;
  };

  const exportReport = () => askEntityExport(testContext, exportUser, EXPORT_FORMAT, report, 'simple', [tlpGreen.id], [tlpClear.id]);

  beforeAll(async () => {
    vi.spyOn(connectorDomain, 'connectorsForExport').mockResolvedValue([EXPORT_CONNECTOR] as Awaited<ReturnType<typeof connectorDomain.connectorsForExport>>);
    vi.spyOn(workDomain, 'createWork').mockResolvedValue({ id: 'export-work-test' });
    vi.spyOn(rabbitmq, 'pushToConnector').mockImplementation(async (_connectorId, message) => {
      connectorMessages.push(message);
      return true;
    });
    exportListener = registerUserActionListener({
      id: 'TEST_EXPORT_ACTIONS',
      next: async (action) => {
        if (action.event_scope === 'export') exportActions.push(action);
      },
    });
    report = await storeLoadById<BasicStoreEntity>(testContext, ADMIN_USER, REPORT_ID, ENTITY_TYPE_CONTAINER_REPORT);
    tlpGreen = await storeLoadById<StoreMarkingDefinition>(testContext, ADMIN_USER, MARKING_TLP_GREEN, ENTITY_TYPE_MARKING_DEFINITION);
    tlpClear = await storeLoadById<StoreMarkingDefinition>(testContext, ADMIN_USER, MARKING_TLP_CLEAR, ENTITY_TYPE_MARKING_DEFINITION);
    exportUser = { ...ADMIN_USER, max_shareable_marking: [tlpGreen] };
    await exportReport();
    await askListExport(testContext, exportUser, { entity_type: ENTITY_TYPE_CONTAINER_REPORT }, EXPORT_FORMAT, [report.id], {}, 'simple', [], []);
    eventIds = exportActions.map((_, index) => `${EVENT_TIMESTAMP}-export-${index}`);
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    exportListener.unregister();
    await elRawDeleteByQuery({ index: READ_INDEX_HISTORY, refresh: true, body: { query: { ids: { values: eventIds } } } });
  });

  it('should define an immutable list of connector only fields', () => {
    expect(EXPORT_CONNECTOR_ONLY_FIELDS).toEqual(['file_markings', 'main_filter', 'access_filter']);
    expect(Object.isFrozen(EXPORT_CONNECTOR_ONLY_FIELDS)).toBe(true);
  });

  it('should still send the connector export parameters to the export connector', () => {
    expect(connectorMessages).toHaveLength(2);
    const [entityMessage, listMessage] = connectorMessages;
    expect(entityMessage.event).toMatchObject({ export_scope: 'single', file_markings: [tlpClear.id], main_filter: expect.any(Object), access_filter: expect.any(Object) });
    expect(listMessage.event).toMatchObject({ export_scope: 'selection', file_markings: [], main_filter: expect.any(Object), access_filter: expect.any(Object) });
  });

  it('should publish the same export context as the connector receives, without the connector export parameters', () => {
    expect(exportActions).toHaveLength(2);
    exportActions.forEach((action, index) => {
      expect(pick(SHARED_EXPORT_KEYS, action.context_data)).toEqual(pick(SHARED_EXPORT_KEYS, connectorMessages[index].event));
      expect(leakedKeys(action.context_data)).toEqual([]);
    });
  });

  it('should keep the exported entity markings on the activity event to preserve its access control', () => {
    const reportMarkings = report[RELATION_OBJECT_MARKING];
    expect(reportMarkings).not.toHaveLength(0);
    expect(exportActions[0].context_data).toMatchObject({ export_scope: 'single', entity_id: report.id, object_marking_refs_ids: reportMarkings });
  });

  it('should keep the connector export parameters out of the History and Activity mappings', () => {
    for (const entityType of [ENTITY_TYPE_HISTORY, ENTITY_TYPE_ACTIVITY]) {
      const contextData = schemaAttributesDefinition.getAttribute(entityType, 'context_data');
      const mappedNames = contextData && 'mappings' in contextData ? contextData.mappings.map(({ name }) => name) : [];
      expect(mappedNames).toEqual(expect.arrayContaining(['format', 'export_type', 'entity_name']));
      expect(mappedNames.filter((name) => EXPORT_CONNECTOR_ONLY_FIELDS.includes(name))).toEqual([]);
    }
  });

  it('should index entity and list export events without storing the connector export parameters', async () => {
    const events = exportActions.map((action, index) => buildSseEvent(eventIds[index], {
      type: 'command',
      event_scope: 'export',
      message: 'asks for export',
      data: action.context_data as ActivityStreamEvent['data'],
    }));
    const elements = await buildActivityHistoryElements(testContext, events);
    await elIndexElements(testContext, SYSTEM_USER, ENTITY_TYPE_ACTIVITY, elements);
    const [entityDocument, listDocument] = await Promise.all(eventIds.map((id) => elRawGet({ id, index: INDEX_HISTORY }))) as { _source: Record<string, unknown> }[];
    expect(entityDocument._source.context_data).toMatchObject({ format: EXPORT_FORMAT, export_type: 'simple', entity_id: report.id });
    expect(entityDocument._source['rel_object-marking.internal_id']).toEqual(report[RELATION_OBJECT_MARKING]);
    expect(listDocument._source.context_data).toMatchObject({ format: EXPORT_FORMAT, export_type: 'simple', entity_name: 'global' });
    expect(leakedKeys(entityDocument._source)).toEqual([]);
    expect(leakedKeys(listDocument._source)).toEqual([]);
  });

  it('should keep the connector export parameters isolated across concurrent exports', async () => {
    const actionsBefore = exportActions.length;
    const messagesBefore = connectorMessages.length;
    await Promise.all(Array.from({ length: CONCURRENT_EXPORTS }, exportReport));
    const actions = exportActions.slice(actionsBefore);
    const messages = connectorMessages.slice(messagesBefore);
    expect(actions).toHaveLength(CONCURRENT_EXPORTS);
    expect(messages).toHaveLength(CONCURRENT_EXPORTS);
    actions.forEach((action) => expect(leakedKeys(action.context_data)).toEqual([]));
    messages.forEach(({ event }) => expect(event).toMatchObject({ file_markings: [tlpClear.id], main_filter: expect.any(Object), access_filter: expect.any(Object) }));
  });
});
