import type { Widget } from '../../../utils/widget/widget';

export interface PublicWidgetContainerProps {
  startDate?: string | null | undefined
  endDate?: string | null | undefined
  uriKey: string
  widget: Widget
  title?: string
}
