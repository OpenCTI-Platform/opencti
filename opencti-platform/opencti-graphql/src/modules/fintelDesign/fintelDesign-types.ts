import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_FINTEL_DESIGN = 'FintelDesign';

export interface FintelDesign {
  name: string;
  description: string;
  file_id: string;
  gradiantFromColor: string;
  gradiantToColor: string;
  textColor: string;
  default?: boolean;
}

// region Database types
export interface BasicStoreEntityFintelDesign extends BasicStoreEntity {
  name: string;
  description: string;
  file_id: string;
  gradiantFromColor: string;
  gradiantToColor: string;
  textColor: string;
  default?: boolean;
}

export interface StoreEntityFintelDesign extends StoreEntity {
  name: string;
  description: string;
  file_id: string;
  gradiantFromColor: string;
  gradiantToColor: string;
  textColor: string;
  default?: boolean;
}
// end region
