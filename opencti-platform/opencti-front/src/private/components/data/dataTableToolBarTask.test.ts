import { describe, it, expect } from 'vitest';
import { buildTaskActions, displayActionValue, normalizeActionValue } from './dataTableToolBarTask';

describe('DataTableToolBar background task', () => {
  it('should keep only the ids of the values, and dates as ISO strings', () => {
    expect(normalizeActionValue({ id: 'id-1', value: 'other' })).toEqual('id-1');
    expect(normalizeActionValue({ label: 'TLP:RED', value: 'id-2' })).toEqual('id-2');
    expect(normalizeActionValue(new Date('2026-01-02T03:04:05.000Z'))).toEqual('2026-01-02T03:04:05.000Z');
    expect(normalizeActionValue('true')).toEqual('true');
  });

  it('should display the values', () => {
    expect(displayActionValue('description')).toEqual('description');
    expect(displayActionValue(new Date('2026-01-02T03:04:05.000Z'))).toEqual('2026-01-02T03:04:05.000Z');
    expect(displayActionValue({ name: 'APT28' })).toEqual('APT28');
  });

  it('should build the actions of the knowledge tasks', () => {
    expect(buildTaskActions([
      { type: 'ADD', context: { field: 'object-label', type: 'RELATION', values: [{ value: 'label-1' }] } },
      { type: 'DELETE', context: null },
    ], { taskScope: 'KNOWLEDGE' })).toEqual([
      { type: 'ADD', context: { field: 'object-label', type: 'RELATION', values: ['label-1'] }, containerId: null },
      { type: 'DELETE', context: null, containerId: null },
    ]);
  });

  it('should promote in the container only when asked', () => {
    const promote = [{ type: 'PROMOTE' }];
    expect(buildTaskActions(promote, { promoteToContainer: true, containerId: 'report-1' })[0].containerId).toEqual('report-1');
    expect(buildTaskActions(promote, { promoteToContainer: false, containerId: 'report-1' })[0].containerId).toEqual(null);
    expect(buildTaskActions(promote, { promoteToContainer: true, containerId: null })[0].containerId).toEqual(null);
  });

  it('should use the dedicated actions for groups and organizations of users', () => {
    expect(buildTaskActions([
      { type: 'ADD', context: { field: 'groups', values: [{ value: 'group-1' }] } },
      { type: 'REMOVE', context: { field: 'organizations', values: [{ value: 'orga-1' }] } },
      { type: 'REPLACE', context: { field: 'account_status', values: [{ label: 'Active', value: 'Active' }] } },
    ], { taskScope: 'USER' })).toEqual([
      { type: 'ADD_GROUPS', context: { field: 'groups', values: ['group-1'] }, containerId: null },
      { type: 'REMOVE_ORGANIZATIONS', context: { field: 'organizations', values: ['orga-1'] }, containerId: null },
      { type: 'REPLACE', context: { field: 'account_status', values: ['Active'] }, containerId: null },
    ]);
  });
});
