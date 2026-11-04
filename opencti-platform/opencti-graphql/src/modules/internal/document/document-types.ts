import type { BasicStoreEntity } from '../../../types/store';

// These storage path constants live in this dependency-free module (rather than document-domain.ts)
// to avoid a circular import evaluation-order issue: document-domain.ts transitively imports
// modules that import file-storage.ts, and file-storage.ts computes ALL_MERGEABLE_FOLDERS/ALL_ROOT_FOLDERS
// at module-load time, which could read these constants before document-domain.ts finished initializing.
export const SUPPORT_STORAGE_PATH = 'support';
export const IMPORT_STORAGE_PATH = 'import';
export const EMBEDDED_STORAGE_PATH = 'embedded';
export const EXPORT_STORAGE_PATH = 'export';
export const FROM_TEMPLATE_STORAGE_PATH = 'fromTemplate';
export const CONFIG_PRESET_STORAGE_PATH = 'config_preset';
export const SYNC_INFLIGHT_STORAGE_PATH = 'sync/inflight';
// Under config_preset/: exports are deleted after one hour, pending imports and import reports are kept
export const CONFIG_PRESET_EXPORT_PATH = `${CONFIG_PRESET_STORAGE_PATH}/export`;
export const CONFIG_PRESET_IMPORT_PATH = `${CONFIG_PRESET_STORAGE_PATH}/import`;
export const CONFIG_PRESET_HISTORY_PATH = `${CONFIG_PRESET_STORAGE_PATH}/history`;

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
    sha256?: string;
    order?: number;
    description?: string;
    inCarousel?: boolean;
    fintel_template_id?: string;
    filename?: string;
    file_markings?: string[];
  };
}
