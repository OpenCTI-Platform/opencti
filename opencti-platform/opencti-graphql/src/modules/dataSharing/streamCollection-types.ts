import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { AuthorizedMember } from '../../utils/access';

export const ENTITY_TYPE_STREAM_COLLECTION = 'StreamCollection';

export interface BasicStoreEntityStreamCollection extends BasicStoreEntity {
  name: string;
  description: string;
  filters: string;
  stream_public: boolean;
  stream_public_user_id?: string | null;
  stream_live: boolean;
  restricted_members: AuthorizedMember[];
}

export interface StoreEntityStreamCollection extends StoreEntity {
  name: string;
  description: string;
  filters: string;
  stream_public: boolean;
  stream_public_user_id?: string | null;
  stream_live: boolean;
}

export interface StixStreamCollection extends StixObject {
  name: string;
  description: string;
  filters: string;
  stream_public: boolean;
  stream_public_user_id?: string | null;
  stream_live: boolean;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
