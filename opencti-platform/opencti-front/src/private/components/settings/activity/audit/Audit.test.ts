import { describe, expect, it } from 'vitest';
import { buildAuditCsvData } from './Audit';

describe('buildAuditCsvData', () => {
  it('includes user metadata in the exported row', () => {
    const userMetadata = { ip: '192.0.2.1', sessionHash: 'session-hash' };

    const [csvRow] = buildAuditCsvData([{
      node: {
        id: 'activity-id',
        entity_type: 'Activity',
        event_type: 'mutation',
        event_scope: 'create',
        event_status: 'success',
        timestamp: '2026-09-25T10:00:00.000Z',
        context_uri: '/dashboard/settings/activity/audit',
        user: { id: 'user-id', name: 'Alice' },
        user_metadata: userMetadata,
        context_data: {
          entity_id: 'entity-id',
          entity_type: 'Indicator',
          entity_name: 'Example indicator',
          message: 'created',
        },
      },
    }]);

    expect(csvRow.user_metadata).toEqual(userMetadata);
  });

  it('uses the fallback when user metadata is absent', () => {
    const [csvRow] = buildAuditCsvData([{
      node: {
        id: 'activity-id',
        event_type: 'mutation',
        event_status: 'success',
        timestamp: '2026-09-25T10:00:00.000Z',
      },
    }]);

    expect(csvRow.user_metadata).toBe('undefined');
  });
});