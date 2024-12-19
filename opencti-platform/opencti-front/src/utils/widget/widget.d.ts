import { FilterGroup } from '../filters/filtersHelpers-types';
import { WidgetPerspective } from '../outcome_template/engine/__generated__/FintelTemplateAndUtilsContainerQuery.graphql';

interface WidgetColumn {
  attribute: string | null
  displayStyle?: string | null
  label?: string | null
  variableName?: string | null
}

interface WidgetDataSelection {
  label?: string | null
  number?: number | null
  attribute?: string | null
  date_attribute?: string | null
  centerLat?: number | null
  centerLng?: number | null
  zoom?: number | null
  isTo?: boolean | null
  perspective?: WidgetPerspective | null
  filters?: FilterGroup | null
  dynamicFrom?: FilterGroup | null
  dynamicTo?: FilterGroup | null
  columns?: readonly WidgetColumn[] | null
  instance_id?: string | null
}

interface WidgetParameters {
  title?: string | null
  interval?: string | null
  stacked?: boolean | null
  legend?: boolean | null
  distributed?: boolean | null
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
  type: string;
  perspective?: WidgetPerspective
  dataSelection: WidgetDataSelection[]
  parameters?: WidgetParameters
  layout?: WidgetLayout
}
