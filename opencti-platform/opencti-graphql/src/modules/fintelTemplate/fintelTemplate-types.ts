import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { FintelTemplateWidget } from '../../generated/graphql';

export const ENTITY_TYPE_FINTEL_TEMPLATE = 'FintelTemplate';

export interface FintelTemplate {
  name: string;
  description: string;
  settings_types: [string];
  instance_filters: string;
  template_content: string;
  fintel_template_widgets: [FintelTemplateWidget];
  start_date: string;
  default?: boolean;
  include_cover_page_by_default?: boolean;
  include_back_page_by_default?: boolean;
}

// region Database types
export interface BasicStoreEntityFintelTemplate extends BasicStoreEntity {
  name: string;
  description: string;
  settings_types: [string];
  instance_filters: string;
  template_content: string;
  fintel_template_widgets: [FintelTemplateWidget];
  start_date: string;
  default?: boolean;
  include_cover_page_by_default?: boolean;
  include_back_page_by_default?: boolean;
}

export interface StoreEntityFintelTemplate extends StoreEntity {
  name: string;
  description: string;
  settings_types: [string];
  instance_filters: string;
  template_content: string;
  fintel_template_widgets: [FintelTemplateWidget];
  start_date: string;
  default?: boolean;
  include_cover_page_by_default?: boolean;
  include_back_page_by_default?: boolean;
}
// endregion
