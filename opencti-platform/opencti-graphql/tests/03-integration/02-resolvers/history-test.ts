import { describe, expect, it } from 'vitest';
import { findHistory } from '../../../src/domain/log';
import { ADMIN_USER, getAuthUser, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { type FilterGroup, FilterMode, LogsOrdering, OrderingMode } from '../../../src/generated/graphql';
import { elLoadById } from '../../../src/database/engine';
import { INDEX_DELETED_OBJECTS } from '../../../src/database/utils';
import { batchContextDataForLog } from '../../../src/database/data-changes';

describe('Testing History search', () => {
  it('Is history is searchable', async () => {
    // Get internal id of deleted malware--284e60cb-6b78-5ca5-a81c-b84b6bc12c02
    const malwareId = 'malware--284e60cb-6b78-5ca5-a81c-b84b6bc12c02';
    const malware = await elLoadById(testContext, ADMIN_USER, malwareId, { indices: [INDEX_DELETED_OBJECTS] });
    expect(malware).not.toBeNull();
    const filters: FilterGroup = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        { key: ['context_data.id'], values: [malware?.internal_id] },
        { key: ['event_type'], values: ['mutation', 'create', 'update', 'delete', 'merge'] },
        { key: ['event_scope'], values: ['update'] },
      ],
    };
    const args = { filters, orderBy: LogsOrdering.CreatedAt, orderMode: OrderingMode.Asc };
    const logs = await findHistory(testContext, ADMIN_USER, args);
    expect(logs.edges.length).toBe(3);
    const firstElementChanges = logs.edges[0].node.context_data.history_changes;
    expect(firstElementChanges.length).toBe(1);
    expect(firstElementChanges[0].field).toBe('Malware--objectMarking');
    expect(firstElementChanges[0].changes_added?.length).toBe(1);
    expect(firstElementChanges[0].changes_removed?.length).toBe(1);
    const raw = firstElementChanges[0].changes_added?.[0].raw ?? '-';
    const translatedRaw = JSON.parse(firstElementChanges[0].changes_added?.[0].translated ?? '{}');
    expect(translatedRaw[raw]).toBe('TLP:TEST');
  });

  it('Is history is filtered with capabilities', async () => {
    const caseId = 'case-incident--482094e5-fd33-5e9e-884d-378bcf425fa3';
    const caseElement = await elLoadById(testContext, ADMIN_USER, caseId, { indices: [INDEX_DELETED_OBJECTS] });
    expect(caseElement).not.toBeNull();
    const filters: FilterGroup = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        { key: ['context_data.id'], values: [caseElement?.internal_id] },
        { key: ['event_type'], values: ['mutation', 'create', 'update', 'delete', 'merge'] },
        { key: ['event_scope'], values: ['update'] },
      ],
    };
    const args = { filters, orderBy: LogsOrdering.CreatedAt, orderMode: OrderingMode.Asc };
    const logs = await findHistory(testContext, ADMIN_USER, args);
    expect(logs.edges.length).toBe(5);
    const firstElementChanges = logs.edges[0].node.context_data.history_changes;
    expect(firstElementChanges.length).toBe(2);
    expect(firstElementChanges[0].field).toBe('Case-Incident--restricted_members');
    expect(firstElementChanges[1].field).toBe('Case-Incident--authorized_members_activation_date');
    const editor = await getAuthUser(USER_PARTICIPATE.id);
    const logsEditor = await findHistory(testContext, editor, args);
    expect(logsEditor.edges.length).toBe(0); // restricted_members event filtered
  });

  it('Is history batchContextDataForLog correctly resolved information', async () => {
    // Get internal id of deleted malware--284e60cb-6b78-5ca5-a81c-b84b6bc12c02
    const malwareId = 'malware--284e60cb-6b78-5ca5-a81c-b84b6bc12c02';
    const malware = await elLoadById(testContext, ADMIN_USER, malwareId, { indices: [INDEX_DELETED_OBJECTS] });
    expect(malware).not.toBeNull();
    const filters: FilterGroup = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        { key: ['context_data.id'], values: [malware?.internal_id] },
        { key: ['event_type'], values: ['mutation', 'create', 'update', 'delete', 'merge'] },
        { key: ['event_scope'], values: ['update'] },
      ],
    };
    const args = { filters, orderBy: LogsOrdering.CreatedAt, orderMode: OrderingMode.Asc };
    const logs = await findHistory(testContext, ADMIN_USER, args);
    expect(logs.edges.length).toBe(3);
    expect(logs.edges[0].node.context_data.message).toBe('Update 1 elements');
    const batchResolvedLogs = await batchContextDataForLog(testContext, ADMIN_USER, logs.edges.map((l) => ({ log: l.node })));
    expect(batchResolvedLogs.length).toBe(3);
    expect(batchResolvedLogs[0].message).toBe('add `TLP:TEST` in `Markings` | removes `TLP:CLEAR` in `Markings`');
  });
});
