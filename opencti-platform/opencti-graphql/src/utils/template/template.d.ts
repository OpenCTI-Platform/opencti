import type { Widget } from './widget';

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

export interface ResolvedAttributesWidget {
  template_widget_name: string,
  displayStyle?: string,
  data: string[],
}
