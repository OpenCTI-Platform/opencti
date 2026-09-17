import type { AuthUser } from '../types/user';
import type { BasicStoreCommon, BasicStoreObject } from '../types/store';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';

interface BasicUserAction {
  user: AuthUser;
  status?: 'success' | 'error'; // nothing = success
  event_type: 'authentication' | 'read' | 'mutation' | 'file' | 'command' | IngestionEventType;
  event_scope: string;
  event_access: 'extended' | 'administration';
  prevent_indexing?: boolean;
}

// region actions
export interface UserSearchActionContextData {
  input: unknown;
  search?: string;
}
export interface UserSearchAction extends BasicUserAction {
  event_type: 'command';
  event_scope: 'search';
  context_data: UserSearchActionContextData;
}

export interface ElementContextData {
  id: string;
  entity_name: string;
  entity_type: string;
  creator_ids?: string[];
  granted_refs_ids?: string[];
  object_marking_refs_ids?: string[];
  object_marking_refs_definitions?: string[];
  created_by_ref_id?: string;
  workspace_type?: string;
  labels_ids?: string[];
}
export interface UserAnalyzeActionContextData extends ElementContextData {
  connector_id: string;
  connector_name: string;
}
export interface UserAnalyzeAction extends BasicUserAction {
  event_type: 'command';
  event_scope: 'analyze';
  context_data: UserAnalyzeActionContextData;
}
export interface UserEnrichActionContextData extends ElementContextData {
  connector_id: string;
  connector_name: string;
}
export interface UserEnrichAction extends BasicUserAction {
  event_type: 'command';
  event_scope: 'enrich';
  context_data: UserEnrichActionContextData;
}
export interface UserImportActionContextData extends ElementContextData {
  file_id: string;
  file_mime: string;
  file_name: string;
  connectors: string[];
}
export interface UserImportAction extends BasicUserAction {
  event_type: 'command';
  event_scope: 'import';
  context_data: UserImportActionContextData;
}
export interface UserExportActionContextData extends ElementContextData {
  format: string;
  entity_type: string;
  export_scope: 'query' | 'single' | 'selection';
  export_type: 'simple' | 'full';
  element_id: string; // Same as id
  max_marking: string;
  list_params?: unknown;
  selected_ids?: string[];
}
export interface UserExportAction extends BasicUserAction {
  event_type: 'command';
  event_scope: 'export';
  context_data: UserExportActionContextData;
}

export interface UserSendActionContextData extends ElementContextData {
  input: unknown;
}

export interface UserSendAction extends BasicUserAction {
  event_type: 'command';
  event_scope: 'send';
  context_data: UserSendActionContextData;
}
// endregion

// region file
export interface UserFileActionContextData extends ElementContextData {
  path: string;
  file_name: string;
  input?: unknown;
}
export interface UserFileAction extends BasicUserAction {
  event_type: 'file';
  event_scope: 'read' | 'create' | 'delete' | 'download';
  context_data: UserFileActionContextData;
}

export interface UserDisseminateActionContextData extends ElementContextData {
  input: unknown;
}
export interface DisseminateAction extends BasicUserAction {
  event_type: 'file';
  event_scope: 'disseminate';
  context_data: UserDisseminateActionContextData;
}
// endregion

// region read / mutation
export interface UserReadActionContextData extends ElementContextData {
  workspace_type?: string;
}
export interface UserReadAction extends BasicUserAction {
  event_type: 'read';
  event_scope: 'read';
  context_data: UserReadActionContextData;
}
export interface UserForbiddenAction extends BasicUserAction {
  event_type: 'read' | 'mutation';
  event_scope: 'unauthorized';
  context_data: {
    operation: string;
    input: unknown;
  };
}
export interface UserModificationAction extends BasicUserAction {
  event_type: 'mutation';
  event_scope: 'create' | 'update' | 'delete';
  message: string;
  context_data: {
    id: string;
    entity_type: string;
    input: unknown;
  };
}
// endregion

// region authentication
export interface UserLoginAction extends BasicUserAction {
  event_type: 'authentication';
  event_scope: 'login';
  session_kill?: number;
  context_data: {
    provider: string;
    username?: string;
  };
}
export interface UserLogoutAction extends BasicUserAction {
  event_type: 'authentication';
  event_scope: 'logout';
  context_data: undefined;
}

export interface UserForgotPasswordAction extends BasicUserAction {
  event_type: 'authentication';
  event_scope: 'forgot';
  context_data: undefined;
  message: string;
}
// endregion

// region ingestion health event taxonomy
//
// Declared here rather than in activityListener because that module imports
// this one — putting them the other way round would be an import cycle. The
// stream taxonomy (EVENT_TYPE_VALUES / EVENT_SCOPE_VALUES) is built from these.

// Two types, one shape. Splitting on the *type* rather than the scope is what
// lets someone build "live alert on bad health" and "daily digest of
// misconfiguration" with the filter keys AlertLiveCreation already offers.
export const EVENT_TYPE_HEALTH = 'health';
export const EVENT_TYPE_CONFIGURATION = 'configuration';

export const INGESTION_EVENT_TYPES = [EVENT_TYPE_HEALTH, EVENT_TYPE_CONFIGURATION] as const;
export type IngestionEventType = typeof INGESTION_EVENT_TYPES[number];

// The scope carries the state entered, not an action, because severity is what
// people subscribe to.
export const EVENT_SCOPE_DEGRADED = 'degraded';
export const EVENT_SCOPE_CRITICAL = 'critical';
export const EVENT_SCOPE_RECOVERED = 'recovered';
export const HEALTH_EVENT_SCOPES = [EVENT_SCOPE_DEGRADED, EVENT_SCOPE_CRITICAL, EVENT_SCOPE_RECOVERED] as const;
export type HealthEventScope = typeof HEALTH_EVENT_SCOPES[number];

// `inventory` is the daily restatement of everything still misconfigured, which
// is what makes a digest an inventory rather than a changelog.
export const EVENT_SCOPE_ADVISORY = 'advisory';
export const EVENT_SCOPE_BLOCKING = 'blocking';
export const EVENT_SCOPE_RESOLVED = 'resolved';
export const EVENT_SCOPE_INVENTORY = 'inventory';
export const CONFIGURATION_EVENT_SCOPES = [
  EVENT_SCOPE_ADVISORY,
  EVENT_SCOPE_BLOCKING,
  EVENT_SCOPE_RESOLVED,
  EVENT_SCOPE_INVENTORY,
] as const;
export type ConfigurationEventScope = typeof CONFIGURATION_EVENT_SCOPES[number];

export const isIngestionEventType = (type: string | undefined): type is IngestionEventType => {
  return INGESTION_EVENT_TYPES.includes(type as IngestionEventType);
};

// endregion

// Ingestion health transitions. Unlike every other action these have no human
// actor: they are emitted by the ingestion health manager, so `user` is the
// system user and the message is pre-rendered (§6.2 of the spec).
export interface UserHealthActionContextData {
  // The source's internal_id — also the key the publisher buffers on.
  id: string;
  entity_type: string;
  source_kind: 'connector' | 'feed' | 'sync';
  source_name: string;
  // Deep-link suffix under /dashboard/integrations/, e.g. `connectors/<id>`.
  source_route: string;
  status: string;
  previous_status?: string;
  since?: string;
  configuration_status?: string;
  checks: Array<{ code: string; kind?: string; severity: string; message: string }>;
}

export interface UserHealthAction extends BasicUserAction {
  event_type: IngestionEventType;
  // Both axes' scopes: the runtime edge emits the first three, the
  // configuration edge the rest.
  event_scope: HealthEventScope | ConfigurationEventScope;
  message: string;
  context_data: UserHealthActionContextData;
}

export type UserAction = UserReadAction | UserFileAction | UserLoginAction | UserEnrichAction | UserAnalyzeAction | UserImportAction
  | UserLogoutAction | UserExportAction | UserSendAction | UserModificationAction | UserForbiddenAction | UserSearchAction | DisseminateAction | UserForgotPasswordAction
  | UserHealthAction;

export interface ActionListener {
  id: string;
  next: (action: UserAction) => Promise<void>;
}
export interface ActionHandler {
  unregister: () => void;
}

const listeners = new Map<string, ActionListener>();

export const registerUserActionListener = (listener: ActionListener): ActionHandler => {
  listeners.set(listener.id, listener);
  return { unregister: () => listeners.delete(listener.id) };
};

export const publishUserAction = async (userAction: UserAction) => {
  const actionPromises = [];
  for (const [, listener] of listeners.entries()) {
    actionPromises.push(listener.next(userAction));
  }
  return Promise.all(actionPromises);
};

export const completeContextDataForEntity = <T extends BasicStoreCommon | null, C extends ElementContextData>(inputContextData: C, data: T) => {
  const contextData = { ...inputContextData };
  if (data) {
    if (data.creator_id) {
      contextData.creator_ids = Array.isArray(data.creator_id) ? data.creator_id : [data.creator_id];
    }
    if (data[RELATION_GRANTED_TO]) {
      contextData.granted_refs_ids = data[RELATION_GRANTED_TO];
    }
    if (data[RELATION_OBJECT_MARKING]) {
      contextData.object_marking_refs_ids = data[RELATION_OBJECT_MARKING];
    }
    if (data[RELATION_CREATED_BY]) {
      contextData.created_by_ref_id = data[RELATION_CREATED_BY];
    }
    if (data[RELATION_OBJECT_LABEL]) {
      contextData.labels_ids = data[RELATION_OBJECT_LABEL];
    }
    if (data.entity_type === ENTITY_TYPE_WORKSPACE) {
      contextData.workspace_type = data.type;
    }
  }
  return contextData;
};

export const buildContextDataForFile = (
  entity: BasicStoreObject | null,
  path: string,
  filename: string,
  file_markings: string[] = [],
  input: unknown = {},
) => {
  const baseData: UserFileActionContextData = {
    path,
    id: entity?.internal_id ?? '',
    entity_name: entity ? extractEntityRepresentativeName(entity) : 'global',
    entity_type: entity?.entity_type ?? 'global',
    file_name: filename,
    object_marking_refs_ids: file_markings,
    input,
  };
  return completeContextDataForEntity(baseData, entity);
};
