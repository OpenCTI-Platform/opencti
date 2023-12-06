import type { BasicStoreEntity } from '../../types/store';

export interface BasicStoreEntityDocument extends BasicStoreEntity {
  file_mime_type: string
  file_updated_at: string
  file_size: number
  entity_id?: string
  metaData: {
    order?: number
    description?: string
    inCarousel?: boolean
  }
}
