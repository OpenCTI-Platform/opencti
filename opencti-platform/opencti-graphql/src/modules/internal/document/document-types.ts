import type { BasicStoreEntity } from '../../../types/store';

export interface BasicStoreEntityDocument extends BasicStoreEntity {
  size: number
  lastModified: Date
  lastModifiedSinceMin: Date
  metaData: {
    entity_id?: string
    mimetype: string
    order?: number
    description?: string
    inCarousel?: boolean
    filename?: string
    file_markings?: string[]
  }
}
