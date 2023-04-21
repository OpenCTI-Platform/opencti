import type { AuthUser } from '../types/user';

interface BasicUserAction {
  user: AuthUser
  status: 'success' | 'error'
  event_type: 'login' | 'logout' | 'read' | 'upload' | 'download' | 'export' | 'admin' | 'unauthorized'
}
export interface UserReadAction extends BasicUserAction {
  event_type: 'read'
  context_data: {
    id: string
    entity_type: string
  }
}
export interface UserForbiddenAction extends BasicUserAction {
  event_type: 'unauthorized'
  context_data: {
    path: string
  }
}
export interface UserDownloadAction extends BasicUserAction {
  event_type: 'download'
  context_data: {
    id: string
    filename: string
  }
}
export interface UserUploadAction extends BasicUserAction {
  event_type: 'upload'
  context_data: {
    id: string
    filename: string
  }
}
export interface UserAdminAction extends BasicUserAction {
  event_type: 'admin'
  context_data: {
    type: string
    data: unknown
  }
}
export interface UserLoginAction extends BasicUserAction {
  event_type: 'login'
  context_data: {
    provider: string
  }
}
export interface UserLogoutAction extends BasicUserAction {
  event_type: 'logout'
  context_data: undefined
}
export interface UserExportAction extends BasicUserAction {
  event_type: 'export'
  context_data: {
    type: 'list' | 'entity'
    max_marking: string
    ids: string[]
    params?: unknown
  }
}
export type UserAction = UserReadAction | UserDownloadAction | UserUploadAction | UserLoginAction |
UserLogoutAction | UserExportAction | UserAdminAction | UserForbiddenAction;

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
