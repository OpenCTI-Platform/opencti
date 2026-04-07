import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_TAXII_COLLECTION = 'TaxiiCollection';

export interface BasicStoreEntityTaxiiCollection extends BasicStoreEntity {
  name: string;
  description: string;
  filters: string;
  taxii_public: boolean;
  taxii_public_user_id?: string | null;
  include_inferences: boolean;
  score_to_confidence: boolean;
}

export interface StoreEntityTaxiiCollection extends StoreEntity {
  name: string;
  description: string;
  filters: string;
  taxii_public: boolean;
  taxii_public_user_id?: string | null;
  include_inferences: boolean;
  score_to_confidence: boolean;
}

export interface StixTaxiiCollection extends StixObject {
  name: string;
  description: string;
  filters: string;
  taxii_public: boolean;
  taxii_public_user_id?: string | null;
  include_inferences: boolean;
  score_to_confidence: boolean;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
