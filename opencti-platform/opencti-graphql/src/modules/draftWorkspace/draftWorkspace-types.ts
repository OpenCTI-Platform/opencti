import type { StixObject } from '../../types/stix-2-1-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { AuthorizedMember } from '../../utils/access';

export const ENTITY_TYPE_DRAFT_WORKSPACE = 'DraftWorkspace';

export interface BasicStoreEntityDraftWorkspace extends BasicStoreEntity {
  name: string
  draft_status: string
  validation_work_id: string
  restricted_members: Array<AuthorizedMember>;
}

export interface StoreEntityDraftWorkspace extends Omit<BasicStoreEntityDraftWorkspace, 'restricted_members'>, StoreEntity {
  restricted_members: Array<AuthorizedMember>;
}

export interface StixDraftWorkspace extends StixObject {
  name: string
  draft_status: string
}
