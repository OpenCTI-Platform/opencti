import type { PublicManifestWidget } from './PublicManifest';

export interface PublicWidgetContainerProps {
  startDate?: string | null | undefined
  endDate?: string | null | undefined
  uriKey: string
  widget: PublicManifestWidget
  title?: string
}
