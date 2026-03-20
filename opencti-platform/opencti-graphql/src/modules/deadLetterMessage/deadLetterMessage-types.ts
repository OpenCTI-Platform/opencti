import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_DEAD_LETTER_MESSAGE = 'DeadLetterMessage';

export interface BasicStoreEntityDeadLetterMessage extends BasicStoreEntity {
  original_connector_id?: string;
}

export interface StoreEntityDeadLetterMessage extends StoreEntity {
  original_connector_id?: string;
}

export interface StixDeadLetterMessage extends StixObject {
  original_connector_id?: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
