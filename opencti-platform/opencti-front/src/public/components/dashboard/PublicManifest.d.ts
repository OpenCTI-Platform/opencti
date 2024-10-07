import type { Widget } from '../../../utils/widget/widget';

export interface PublicManifestConfig {
  startDate?: string
  endDate?: string
  relativeDate?: string
}

export interface PublicManifest {
  config?: PublicManifestConfig
  widgets?: Record<string, Widget>
}
