import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { AuthorizedMember } from '../../utils/access';

export const ENTITY_TYPE_WORKSPACE = 'Workspace';

// region Database types
export interface BasicStoreEntityWorkspace extends BasicStoreEntity {
  name: string;
  description: string;
  graph_data: string;
  manifest: string;
  tags: Array<string>;
  type: string;
  authorized_members: Array<AuthorizedMember>;
  object_refs: Array<string>;
  investigated_entities_ids: Array<string>;
}

export interface StoreEntityWorkspace extends StoreEntity {
  name: string;
  description: string;
  graph_data: string;
  manifest: string;
  tags: Array<string>;
  type: string;
  authorized_members: Array<AuthorizedMember>;
  object_refs: Array<string>;
}
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
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
// endregion
