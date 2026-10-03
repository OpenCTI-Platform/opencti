import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { AuthorizedMember } from '../../utils/access';

export const ENTITY_TYPE_WORKSPACE = 'Workspace';

// region Database types
export interface BasicStoreEntityWorkspace extends BasicStoreEntity {
  name: string;
  description: string;
  graph_data: string;
  manifest: string;
  refresh_interval?: number | null;
  tags: Array<string>;
  type: string;
  restricted_members: Array<AuthorizedMember>;
  object_refs: Array<string>;
  investigated_entities_ids: Array<string>;
}

export interface StoreEntityWorkspace extends StoreEntity {
  name: string;
  description: string;
  graph_data: string;
  manifest: string;
  refresh_interval?: number | null;
  tags: Array<string>;
  type: string;
  restricted_members: Array<AuthorizedMember>;
  object_refs: Array<string>;
  investigated_entities_ids: Array<string>;
}
// endregion
