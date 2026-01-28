import { describe, expect, it } from 'vitest';
import { findHistory, findById, findAudits } from '../../../src/domain/log';
import { ADMIN_USER, getAuthUser, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { type FilterGroup, FilterMode, LogsOrdering, OrderingMode, type QueryAuditsArgs, type QueryLogsArgs } from '../../../src/generated/graphql';
import { elLoadById } from '../../../src/database/engine';
import { INDEX_DELETED_OBJECTS } from '../../../src/database/utils';
import { batchContextDataForLog } from '../../../src/database/data-changes';
import type { BasicConnection } from '../../../src/types/store';

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
    const caseId = 'case-incident--019839f8-3220-5fe2-b937-404fe19ef54a';
    const caseElement = await elLoadById(testContext, ADMIN_USER, caseId, { indices: [INDEX_DELETED_OBJECTS] });
    expect(caseElement).toBeDefined();
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
    let firstElementChanges = logs.edges[0].node.context_data.history_changes;
    expect(firstElementChanges.length).toBe(2);
    expect(firstElementChanges[0].field).toBe('Case-Incident--restricted_members');
    expect(firstElementChanges[1].field).toBe('Case-Incident--authorized_members_activation_date');
    // Try limited admin
    const limitedAdmin = { ...ADMIN_USER, capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] };
    const logsLimited = await findHistory(testContext, limitedAdmin, args);
    expect(logsLimited.edges.length).toBe(2);
    firstElementChanges = logsLimited.edges[0].node.context_data.history_changes;
    expect(firstElementChanges.length).toBe(1);
    // only authorized_members_activation_date is available because not restricted for TEST only
    expect(firstElementChanges[0].field).toBe('Case-Incident--authorized_members_activation_date');
    const secondElementChanges = logsLimited.edges[1].node.context_data.history_changes;
    expect(secondElementChanges.length).toBe(2);
    expect(secondElementChanges[0].field).toBe('Case-Incident--name');
    expect(secondElementChanges[0].changes_removed?.[0].raw).toBe('Case Incident Response With Authorized Members from entity');
    expect(secondElementChanges[0].changes_added?.[0].raw).toBe('Case Incident Response - updated');
    expect(secondElementChanges[1].field).toBe('Case-Incident--standard_id');
    // Validate the dedicated log loading
    const monoElement = await findById(testContext, limitedAdmin, logsLimited.edges[0].node.id);
    const monoElementChanges = monoElement.context_data.history_changes;
    expect(monoElementChanges.length).toBe(1);
    expect(monoElementChanges[0].field).toBe('Case-Incident--authorized_members_activation_date');
    // User do not pass restricted members
    const editor = await getAuthUser(USER_PARTICIPATE.id);
    const logsEditor = await findHistory(testContext, editor, args);
    expect(logsEditor.edges.length).toBe(0);
  });

  it('Is history is searchable by keyword', async () => {
    const args: QueryLogsArgs = { orderBy: LogsOrdering.CreatedAt, orderMode: OrderingMode.Asc };
    let logs = await findHistory(testContext, ADMIN_USER, { search: 'Administrative-Area', ...args });
    logs = await findHistory(testContext, ADMIN_USER, { search: '"TO DESC UPPER"', ...args });
    console.log(JSON.stringify(logs, null, 2));
    expect(logs.edges.length).toBe(2);
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

  it('Is history batchContextDataForLog resolved for old changes format', async () => {
    const log = {
      context_data: {
        message: 'Message previously generated',
        changes: [
          { field: 'Markings', new: [], previous: [], added: ['TLP:CLEAR'], removed: ['TLP:TEST'] },
          { field: 'Description', new: ['Description'], previous: ['Old description'], added: [], removed: [] },
        ],
      },
    };
    const batchResolvedLogs = await batchContextDataForLog(testContext, ADMIN_USER, [{ log }]);
    expect(batchResolvedLogs.length).toBe(1);
    expect(batchResolvedLogs[0].message).toBe('Message previously generated');
    expect(batchResolvedLogs[0].changes.length).toBe(2);
    expect(batchResolvedLogs[0].changes[0].field).toBe('Markings');
    expect(batchResolvedLogs[0].changes[0].changes_added).toEqual(['TLP:CLEAR']);
    expect(batchResolvedLogs[0].changes[0].changes_removed).toEqual(['TLP:TEST']);
    expect(batchResolvedLogs[0].changes[1].field).toBe('Description');
    expect(batchResolvedLogs[0].changes[1].changes_added).toEqual(['Description']);
    expect(batchResolvedLogs[0].changes[1].changes_removed).toEqual(['Old description']);
  });

  it('Is Audit is searchable', async () => {
    const args: QueryAuditsArgs = { first: 5, types: ['Activity'], orderBy: LogsOrdering.Timestamp, orderMode: OrderingMode.Asc };
    const audits = await findAudits(testContext, ADMIN_USER, args) as BasicConnection<any>;
    expect(audits.edges.length).toBe(5);
  });

  it('Is Audit + history is searchable', async () => {
    const malwareId = 'malware--284e60cb-6b78-5ca5-a81c-b84b6bc12c02';
    const malware = await elLoadById(testContext, ADMIN_USER, malwareId, { indices: [INDEX_DELETED_OBJECTS] });
    expect(malware).not.toBeNull();
    const filters: FilterGroup = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        { key: ['contextEntityId'], values: [malware?.internal_id] },
        { key: ['event_type'], values: ['mutation', 'create', 'update', 'delete', 'merge'] },
        { key: ['event_scope'], values: ['update'] },
      ],
    };
    const args: QueryAuditsArgs = { filters, types: ['History', 'Activity'], orderBy: LogsOrdering.Timestamp, orderMode: OrderingMode.Asc };
    const audits = await findAudits(testContext, ADMIN_USER, args) as BasicConnection<any>;
    expect(audits.edges.length).toBe(3);
  });

  it('Is audit is filtered with capabilities', async () => {
    const caseId = 'case-incident--019839f8-3220-5fe2-b937-404fe19ef54a';
    const caseElement = await elLoadById(testContext, ADMIN_USER, caseId, { indices: [INDEX_DELETED_OBJECTS] });
    expect(caseElement).toBeDefined();
    const filters: FilterGroup = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        { key: ['contextEntityId'], values: [caseElement?.internal_id] },
        { key: ['event_type'], values: ['mutation', 'create', 'update', 'delete', 'merge'] },
        { key: ['event_scope'], values: ['update'] },
      ],
    };
    const args: QueryAuditsArgs = { filters, types: ['History', 'Activity'], orderBy: LogsOrdering.Timestamp, orderMode: OrderingMode.Asc };
    const logs = await findAudits(testContext, ADMIN_USER, args) as BasicConnection<any>;
    expect(logs.edges.length).toBe(5);
    const firstElementChanges = logs.edges[0].node.context_data.history_changes;
    expect(firstElementChanges.length).toBe(2);
    expect(firstElementChanges[0].field).toBe('Case-Incident--restricted_members');
    expect(firstElementChanges[1].field).toBe('Case-Incident--authorized_members_activation_date');
    // Try limited admin
    const limitedAdmin = { ...ADMIN_USER, capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] };
    const logsLimited = await findAudits(testContext, limitedAdmin, args) as BasicConnection<any>;
    expect(logsLimited.edges.length).toBe(2);
  });
});
