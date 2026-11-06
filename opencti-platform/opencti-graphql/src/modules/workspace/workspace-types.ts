import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
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

// region Investigation status of a work
// Review state of a work linked to an investigation: TO_REVIEW once it completes with something new, DONE once reviewed.
export const WORK_INVESTIGATION_STATUS_TO_REVIEW = 'TO_REVIEW';
export const WORK_INVESTIGATION_STATUS_DONE = 'DONE';
export const WORK_INVESTIGATION_STATUS_VALUES = [WORK_INVESTIGATION_STATUS_TO_REVIEW, WORK_INVESTIGATION_STATUS_DONE];
// endregion

// region Stix type
export interface StixWorkspace extends StixDomainObject {
  name: string;
  description: string;
  graph_data: string;
  manifest: string;
  tags: Array<string>;
  type: string;
  object_refs: Array<string>;
  aliases: Array<string>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
