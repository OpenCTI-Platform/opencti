import type { BasicStoreEntity } from '../../../types/store';

export interface BasicStoreEntityDocument extends BasicStoreEntity {
  size: number
  lastModified: Date
  lastModifiedSinceMin: Date
  uploadStatus: string,
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
