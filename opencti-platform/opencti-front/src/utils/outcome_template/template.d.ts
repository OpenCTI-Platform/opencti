import type { Widget, WidgetFromBackend } from '../widget/widget';

export interface Template {
  id: string
  name: string
  description?: string
  content: string
  used_widgets: string[]
}

export interface TemplateWidget {
  name: string
  widget: Widget
}

export interface TemplateWidgetFromBackend {
  name: string
  widget: WidgetFromBackend
}
