import type { Widget } from '../../../utils/widget/widget';

export interface CustomViewManifestConfig {
  startDate?: string;
  endDate?: string;
  relativeDate?: string;
}

export interface CustomViewManifest {
  config?: CustomViewManifestConfig;
  widgets?: Record<string, Widget>;
}
