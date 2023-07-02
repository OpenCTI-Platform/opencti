import type { AuthUser } from '../types/user';
import { extractEntityRepresentative } from '../database/utils';
import type { BasicStoreObject } from '../types/store';

interface BasicUserAction {
  user: AuthUser
  status?: 'success' | 'error' // nothing = success
  event_type: 'authentication' | 'read' | 'mutation' | 'file' | 'command'
  event_access: 'extended' | 'administration'
  prevent_indexing?: boolean
}

// region actions
export interface UserSearchAction extends BasicUserAction {
  event_type: 'command'
  event_scope: 'search'
  context_data: {
    input: unknown,
  }
}
export interface UserEnrichAction extends BasicUserAction {
  event_type: 'command'
  event_scope: 'enrich'
  context_data: {
    id: string
    entity_name: string
    entity_type: string
    connector_id: string
    connector_name: string
  }
}
export interface UserImportAction extends BasicUserAction {
  event_type: 'command'
  event_scope: 'import'
  context_data: {
    id: string,
    file_id: string,
    file_mime: string,
    file_name: string,
    connectors: string[],
    entity_name: string,
    entity_type: string
  }
}
export interface UserExportAction extends BasicUserAction {
  event_type: 'command'
  event_scope: 'export'
  context_data: {
    id: string
    format: string
    entity_name: string
    entity_type: string
    export_scope: 'query' | 'single' | 'selection'
    export_type: 'simple' | 'full'
    element_id: string // Same as id
    max_marking: string
    list_params?: unknown,
    selected_ids?: string[]
  }
}
// endregion

// region file
export interface UserFileAction extends BasicUserAction {
  event_type: 'file'
  event_scope: 'read' | 'create' | 'delete'
  context_data: {
    id: string
    path: string
    entity_name: string
    entity_type: string
    file_name: string
  }
}
// endregion

// region read / mutation
export interface UserReadAction extends BasicUserAction {
  event_type: 'read'
  event_scope: 'read'
  context_data: {
    id: string
    entity_name: string
    entity_type: string
  }
}
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
  event_scope: 'create' | 'update' | 'delete'
  message: string
  context_data: {
    id: string
    entity_type: string
    input: unknown
  }
}
// endregion

// region authentication
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

export type UserAction = UserReadAction | UserFileAction | UserLoginAction | UserEnrichAction | UserImportAction |
UserLogoutAction | UserExportAction | UserModificationAction | UserForbiddenAction | UserSearchAction;

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
