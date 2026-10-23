export type ToolBarBulkAction = 'merge' | 'addInContainer' | 'update' | 'scan' | 'enrich' | 'share';

// Internal types: no bulk action is available on them from the toolbar
const typesWithoutBulkActions = [
  'Playbook',
  'Label',
  'Case-Template',
  'DeleteOperation',
  'InternalFile',
  'PublicDashboard',
  'Workspace',
  'DraftWorkspace',
  'Notification',
];

// Other types where only some bulk actions are disabled
const disabledBulkActionsByType: Record<string, ToolBarBulkAction[]> = {
  Vocabulary: ['addInContainer', 'update', 'scan', 'enrich', 'share'],
  Task: ['merge', 'update', 'scan', 'enrich'],
  Indicator: ['merge'],
  Note: ['merge'],
  Opinion: ['merge'],
};

export const isBulkActionAllowed = (action: ToolBarBulkAction, entityType: string | undefined): boolean => {
  if (!entityType) return true;
  if (typesWithoutBulkActions.includes(entityType)) return false;
  return !(disabledBulkActionsByType[entityType] ?? []).includes(action);
};

// The action is disabled if the first selected type does not allow it,
// or if the list is filtered on exactly one entity type that does not allow it
export const isBulkActionDisabled = (
  action: ToolBarBulkAction,
  selectedTypes: string[],
  entityTypeFilterValues: string[],
): boolean => {
  return !isBulkActionAllowed(action, selectedTypes[0])
    || (entityTypeFilterValues.length === 1 && !isBulkActionAllowed(action, entityTypeFilterValues[0]));
};
