import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject } from '../../types/stix-2-1-common';

export const ENTITY_TYPE_WORKSPACE_USER_STATE = 'WorkspaceUserState';

export interface BasicStoreEntityWorkspaceUserState extends BasicStoreEntity {
  workspace_id: string;
  /** serialised JSON: Record<variableId, value> */
  variable_values: string;
}

export interface StoreEntityWorkspaceUserState extends StoreEntity {
  workspace_id: string;
  variable_values: string;
}

export interface StixWorkspaceUserState extends StixObject {
  workspace_id: string;
  variable_values: string;
}
