import type { BasicStoreEntity } from '../../../types/store';

export type EntityFileReference = {
  id: string;
  name: string;
  version?: string;
  mime_type?: string;
  file_markings: string[];
};

export type OpenCTIFile = {
  name: string;
  description?: string;
  version: string;
  mime_type: string;
  inCarousel: string;
  file_markings: string[];
  order: number;
};

export interface BasicStoreEntityDocument extends BasicStoreEntity {
  size: number;
  lastModified: Date;
  lastModifiedSinceMin: Date;
  uploadStatus: string;
  metaData: {
    entity_id?: string;
    mimetype: string;
    order?: number;
    description?: string;
    inCarousel?: boolean;
    filename?: string;
    file_markings?: string[];
  };
}
