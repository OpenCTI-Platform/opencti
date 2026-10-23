import { describe, it, expect } from 'vitest';
import { isBulkActionAllowed, isBulkActionDisabled, type ToolBarBulkAction } from './dataTableToolBarActionRules';

// Lists previously hard-coded in DataTableToolBar.jsx, kept here to check the rules did not change
const legacyDisabledTypes: Record<ToolBarBulkAction, string[]> = {
  merge: ['Playbook', 'Indicator', 'Note', 'Opinion', 'Label', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'],
  addInContainer: ['Playbook', 'Label', 'Vocabulary', 'Case-Template', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'],
  update: ['Playbook', 'Label', 'Vocabulary', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'],
  scan: ['Playbook', 'Label', 'Vocabulary', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'],
  enrich: ['Playbook', 'Label', 'Vocabulary', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'],
  share: ['Playbook', 'Label', 'Vocabulary', 'Case-Template', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'],
};

const actions = Object.keys(legacyDisabledTypes) as ToolBarBulkAction[];
const knownTypes = [...new Set(Object.values(legacyDisabledTypes).flat())];
const otherTypes = ['Malware', 'Report', 'IPv4-Addr', 'Stix-Core-Object', 'stix-core-relationship'];

describe('DataTableToolBar action rules', () => {
  it.each(actions)('should match the legacy list for action %s', (action) => {
    [...knownTypes, ...otherTypes].forEach((type) => {
      expect(isBulkActionAllowed(action, type), `${action} on ${type}`)
        .toEqual(!legacyDisabledTypes[action].includes(type));
    });
  });

  it('should allow every action when no type is known', () => {
    actions.forEach((action) => {
      expect(isBulkActionAllowed(action, undefined)).toEqual(true);
    });
  });

  it('should disable an action from the first selected type', () => {
    expect(isBulkActionDisabled('update', ['Task', 'Malware'], [])).toEqual(true);
    expect(isBulkActionDisabled('update', ['Malware', 'Task'], [])).toEqual(false);
  });

  it('should disable an action from the entity type filter only when it has one value', () => {
    expect(isBulkActionDisabled('enrich', [], ['Vocabulary'])).toEqual(true);
    expect(isBulkActionDisabled('enrich', [], ['Vocabulary', 'Malware'])).toEqual(false);
    expect(isBulkActionDisabled('enrich', [], [])).toEqual(false);
  });
});
