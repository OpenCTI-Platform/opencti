import type { Widget } from '../widget/widget';

export interface Template {
  name: string
  description?: string
  content: string
  used_widgets: string[]
}

export interface TemplateWidget {
  name: string
  widget: Widget
}

export interface ResolvedAttributesWidgets {
  template_widget_name: string,
  data: string,
}
