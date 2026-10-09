import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_CUSTOM_VIEW = 'CustomView';

// region Database types
export interface BasicStoreEntityCustomView extends BasicStoreEntity {
  name: string;
  description: string;
  slug: string;
  manifest: string;
  target_entity_type: string;
  enabled?: boolean;
  default?: boolean;
}

export interface StoreEntityCustomView extends StoreEntity {
  name: string;
  description: string;
  slug: string;
  manifest: string;
  target_entity_type: string;
  enabled?: boolean;
  default?: boolean;
}
// endregion

export interface CustomViewExport {
  openCTI_version: string;
  type: 'custom-view';
  configuration: {
    name: string;
    manifest: string;
    target_entity_type?: string;
  };
}
