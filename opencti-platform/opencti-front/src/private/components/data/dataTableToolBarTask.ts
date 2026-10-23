import { getMainRepresentative } from '../../../utils/defaultRepresentatives';

// An action of a background task, as prepared by the toolbar
export interface ToolBarAction {
  type: string;
  context?: {
    field?: string;
    type?: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    values: any[];
    options?: Record<string, boolean>;
  } | null;
}

interface TaskActionOptions {
  taskScope?: string | null;
  promoteToContainer?: boolean;
  containerId?: string | null;
}

// On the users list, adding or removing groups and organizations are dedicated actions
const getUserActionType = (type: string, field?: string) => {
  if (type === 'ADD' && field === 'groups') return 'ADD_GROUPS';
  if (type === 'ADD' && field === 'organizations') return 'ADD_ORGANIZATIONS';
  if (type === 'REMOVE' && field === 'groups') return 'REMOVE_GROUPS';
  if (type === 'REMOVE' && field === 'organizations') return 'REMOVE_ORGANIZATIONS';
  return type;
};

// The task only keeps the ids of the selected values, and dates as ISO strings
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const normalizeActionValue = (element: any) => {
  if (element?.id) return element.id;
  if (element?.value) return element.value;
  if (typeof element?.toISOString === 'function') return element.toISOString();
  return element;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const displayActionValue = (element: any): string => {
  if (typeof element === 'string') return element;
  if (typeof element?.toISOString === 'function') return element.toISOString();
  return getMainRepresentative(element);
};

export const buildTaskActions = (actions: ToolBarAction[], { taskScope, promoteToContainer, containerId }: TaskActionOptions) => {
  if (taskScope === 'USER') {
    return actions.map((action) => ({
      type: getUserActionType(action.type, action.context?.field),
      context: {
        ...action.context,
        values: (action.context?.values ?? []).map(normalizeActionValue),
      },
      containerId: null,
    }));
  }
  return actions.map((action) => ({
    type: action.type,
    context: action.context
      ? { ...action.context, values: action.context.values.map(normalizeActionValue) }
      : null,
    containerId: action.type === 'PROMOTE' && promoteToContainer && containerId ? containerId : null,
  }));
};
