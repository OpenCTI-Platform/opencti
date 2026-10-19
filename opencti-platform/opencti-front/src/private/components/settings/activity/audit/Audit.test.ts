import { describe, expect, it } from 'vitest';
import { buildAuditCsvData, escapeCsvValue, toCsvSafeJson } from './Audit';

describe('toCsvSafeJson', () => {
  it('doubles inner double quotes so react-csv does not truncate the field', () => {
    const userAgent = { 'user-agent': 'Mozilla/5.0 (KHTML, like Gecko)' };

    expect(toCsvSafeJson(userAgent)).toBe('{""user-agent"":""Mozilla/5.0 (KHTML, like Gecko)""}');
  });

  it('returns the literal fallback for empty values', () => {
    expect(toCsvSafeJson(undefined)).toBe('undefined');
    expect(toCsvSafeJson(null)).toBe('undefined');
  });

  it('keeps falsy scalars instead of treating them as missing', () => {
    expect(toCsvSafeJson(false)).toBe('false');
    expect(toCsvSafeJson(0)).toBe('0');
  });

  it('falls back instead of throwing on non-serializable values', () => {
    expect(toCsvSafeJson(() => {})).toBe('undefined');
  });
});

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

    expect(csvRow.user_metadata).toBe(toCsvSafeJson(userMetadata));
  });

  it('exports the relationship and change fields shown in the UI', () => {
    const changes = [{ field: 'description', changes_added: ['new'], changes_removed: ['old'] }];

    const [csvRow] = buildAuditCsvData([{
      node: {
        id: 'activity-id',
        event_type: 'mutation',
        event_status: 'success',
        timestamp: '2026-09-25T10:00:00.000Z',
        context_data: {
          message: 'updates the relationship',
          from_id: 'from-entity-id',
          to_id: 'to-entity-id',
          changes,
        },
      },
    }]);

    expect(csvRow.context_data_from_id).toBe('from-entity-id');
    expect(csvRow.context_data_to_id).toBe('to-entity-id');
    expect(csvRow.context_data_changes).toBe(toCsvSafeJson(changes));
  });

  it('keeps the legacy columns in place and appends the new ones', () => {
    const [csvRow] = buildAuditCsvData([{
      node: { id: 'activity-id', event_type: 'mutation', event_status: 'success', timestamp: '2026-09-25T10:00:00.000Z' },
    }]);

    expect(Object.keys(csvRow)).toEqual([
      'id',
      'entity_type',
      'event_type',
      'event_scope',
      'event_status',
      'timestamp',
      'context_uri',
      'user_id',
      'user_name',
      'context_data_id',
      'context_data_entity_type',
      'context_data_entity_name',
      'context_data_message',
      'user_metadata',
      'context_data_from_id',
      'context_data_to_id',
      'context_data_changes',
    ]);
  });

  it('escapes double quotes in plain string columns', () => {
    const [csvRow] = buildAuditCsvData([{
      node: {
        id: 'activity-id',
        event_type: 'mutation',
        event_status: 'success',
        timestamp: '2026-09-25T10:00:00.000Z',
        user: { id: 'user-id', name: 'Alice "admin"' },
        context_data: {
          entity_name: 'Report "APT"',
          message: 'updates `description` to "new"',
        },
      },
    }]);

    expect(csvRow.user_name).toBe('Alice ""admin""');
    expect(csvRow.context_data_entity_name).toBe('Report ""APT""');
    expect(csvRow.context_data_message).toBe('updates `description` to ""new""');
  });
});

describe('escapeCsvValue', () => {
  it('doubles inner double quotes in strings', () => {
    expect(escapeCsvValue('say "hi"')).toBe('say ""hi""');
  });

  it('leaves non-string values untouched', () => {
    expect(escapeCsvValue(null)).toBeNull();
    expect(escapeCsvValue(undefined)).toBeUndefined();
  });
});
