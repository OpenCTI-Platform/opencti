import { FilterGroup } from '../filters/filtersHelpers-types';
import { TemplateAndUtilsContainerQuery$data, WidgetPerspective } from '../outcome_template/engine/__generated__/TemplateAndUtilsContainerQuery.graphql';

interface WidgetColumn {
  attribute: string
  displayStyle?: string
  label?: string
  variableName?: string
}

interface WidgetDataSelection {
  label?: string
  number?: number
  attribute?: string
  date_attribute?: string
  centerLat?: number
  centerLng?: number
  zoom?: number
  isTo?: boolean
  perspective?: WidgetPerspective
  filters?: FilterGroup
  dynamicFrom?: FilterGroup
  dynamicTo?: FilterGroup
  columns?: WidgetColumn[]
  instance_id?: string
}

interface WidgetParameters {
  title?: string
  interval?: string
  stacked?: boolean
  legend?: boolean
  distributed?: boolean
}

interface WidgetLayout {
  w: number
  h: number
  x: number
  y: number
  i: string
  moved: boolean
  static: boolean
}

export interface Widget {
  id: string;
  type: string;
  perspective?: WidgetPerspective
  dataSelection: WidgetDataSelection[]
  parameters?: WidgetParameters
  layout?: WidgetLayout
}

export type WidgetFromBackend = NonNullable<NonNullable<NonNullable<TemplateAndUtilsContainerQuery$data['container']>['templateAndUtils']>['template_widgets']>[0]['widget'];
