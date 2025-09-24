import { FilterGroup } from '../filters/filtersHelpers-types';

export type WidgetContext = 'workspace' | 'fintelTemplate';

export type WidgetPerspective = 'audits' | 'entities' | 'relationships' | '%future added value';

interface WidgetColumn {
  attribute: string | null
  displayStyle?: string | null
  label?: string | null
  variableName?: string | null
}

export interface WidgetDataSelection {
  label?: string | null
  number?: number | null
  attribute?: string | null
  date_attribute?: string | null
  centerLat?: number | null
  centerLng?: number | null
  zoom?: number | null
  isTo?: boolean | null
  instance_id?: string | null
  perspective?: WidgetPerspective | null
  filters?: FilterGroup | null
  dynamicFrom?: FilterGroup | null
  dynamicTo?: FilterGroup | null
  columns?: readonly WidgetColumn[] | null
  sort_by?: string | null
  sort_mode?: string | null
  field?: string
}

interface WidgetParameters {
  title?: string | null
  interval?: string | null
  stacked?: boolean | null
  legend?: boolean | null
  distributed?: boolean | null
  content?: string | null
  uniqueUsers?: boolean | null
  intervalUniqueUsers?: string | null
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
  perspective?: WidgetPerspective | null
  dataSelection: WidgetDataSelection[]
  parameters?: WidgetParameters | null
  layout?: WidgetLayout | null
}

interface PirWidgetDataSelection extends WidgetDataSelection {
  pirId: string,
}
