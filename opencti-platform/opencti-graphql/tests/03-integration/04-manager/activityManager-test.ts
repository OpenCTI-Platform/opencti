import { describe, expect, it } from 'vitest';
import { testContext } from '../../utils/testQuery';
import activityManager, { buildActivityHistoryElements, getLiveActivityNotifications } from '../../../src/manager/activityManager';
import { INDEX_HISTORY } from '../../../src/database/utils';
import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY } from '../../../src/schema/internalObject';
import type { ActivityStreamEvent, SseEvent } from '../../../src/types/event';

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

