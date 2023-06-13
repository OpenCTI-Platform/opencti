import type { AuthUser } from '../types/user';
import { extractEntityRepresentative } from '../database/utils';
import type { BasicStoreObject } from '../types/store';

interface BasicUserAction {
  user: AuthUser
  status?: 'success' | 'error' // nothing = success
  explicit_listening?: boolean
  event_type: 'authentication' | 'read' | 'mutation'
  event_access: 'standard' | 'administration'
  event_scope: 'download' | 'upload' | 'export' | 'unauthorized' | 'login' | 'logout' | 'read' | 'create' | 'update' | 'delete' | 'merge' | 'search'
}

// region user explicit listening
export interface UserReadAction extends BasicUserAction {
  event_type: 'read'
  event_scope: 'read' | 'search'
  context_data: {
    id: string
    entity_name: string
    entity_type: string
  }
}
export interface UserDownloadAction extends BasicUserAction {
  event_type: 'read'
  event_scope: 'download'
  context_data: {
    id: string
    path: string
    entity_name: string
    entity_type: string
    file_name: string
  }
}
export interface UserUploadAction extends BasicUserAction {
  event_type: 'mutation'
  event_scope: 'upload'
  context_data: {
    id: string
    path: string
    entity_name: string
    entity_type: string
    file_name: string
  }
}
export interface UserExportAction extends BasicUserAction {
  event_type: 'mutation'
  event_scope: 'export'
  context_data: {
    export_scope: 'query' | 'single' | 'selection'
    export_type: 'simple' | 'full'
    id: string
    element_id: string // Same as id
    entity_name: string
    entity_type: string
    file_name: string
    max_marking: string
    list_params?: unknown,
    selected_ids?: string[]
  }
}
// endregion

// region standard
export interface UserForbiddenAction extends BasicUserAction {
  event_type: 'read' | 'mutation'
  event_scope: 'unauthorized'
  context_data: {
    operation: string
    input: unknown,
  }
}
export interface UserModificationAction extends BasicUserAction {
  event_type: 'mutation'
  event_scope: 'create' | 'update' | 'delete' | 'merge'
  message: string
  context_data: {
    entity_type: string
    input: unknown
  }
}
export interface UserLoginAction extends BasicUserAction {
  event_type: 'authentication'
  event_scope: 'login'
  context_data: {
    provider: string
    username: string
  }
}
export interface UserLogoutAction extends BasicUserAction {
  event_type: 'authentication'
  event_scope: 'logout'
  context_data: undefined
}
// endregion

export type UserAction = UserReadAction | UserDownloadAction | UserUploadAction | UserLoginAction |
UserLogoutAction | UserExportAction | UserModificationAction | UserForbiddenAction;

export interface ActionListener {
  id: string
  next: (action: UserAction) => Promise<void>
}
export interface ActionHandler {
  unregister: () => void
}

const listeners = new Map<string, ActionListener>();

export const registerUserActionListener = (listener: ActionListener): ActionHandler => {
  listeners.set(listener.id, listener);
  return { unregister: () => listeners.delete(listener.id) };
};

export const publishUserAction = async (userAction: UserAction) => {
  const actionPromises = [];
  // eslint-disable-next-line no-restricted-syntax
  for (const [, listener] of listeners.entries()) {
    actionPromises.push(listener.next(userAction));
  }
  return Promise.all(actionPromises);
};

export const buildContextDataForFile = (entity: BasicStoreObject, path: string, filename: string) => {
  return {
    path,
    id: entity?.internal_id,
    entity_name: entity ? extractEntityRepresentative(entity) : 'global',
    entity_type: entity?.entity_type ?? 'global',
    file_name: filename
  };
};
