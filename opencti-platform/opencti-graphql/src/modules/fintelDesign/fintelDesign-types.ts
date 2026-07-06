import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';

export const ENTITY_TYPE_FINTEL_DESIGN = 'FintelDesign';

export interface FintelDesign {
  name: string;
  description: string;
  file_id: string;
  gradiantFromColor: string;
  gradiantToColor: string;
  textColor: string;
  default: boolean;
}

// region Database types
export interface BasicStoreEntityFintelDesign extends BasicStoreEntity {
  name: string;
  description: string;
  file_id: string;
  gradiantFromColor: string;
  gradiantToColor: string;
  textColor: string;
  default: boolean;
}

export interface StoreEntityFintelDesign extends StoreEntity {
  name: string;
  description: string;
  file_id: string;
  gradiantFromColor: string;
  gradiantToColor: string;
  textColor: string;
  default: boolean;
}
// end region

// region Stix type
export interface StixFintelDesign extends StixObject {
  name: string;
  description: string;
  file_id: string;
  gradiantFromColor: string;
  gradiantToColor: string;
  textColor: string;
  default: boolean;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
