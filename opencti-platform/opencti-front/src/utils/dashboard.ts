import { FilterGroup } from './filters/filtersHelpers-types';

export interface DashboardWidgetDataSelection {
  label?: string
  number?: number
  attribute?: string
  date_attribute?: string
  centerLat?: number
  centerLng?: number
  zoom?: number
  isTo?: boolean
  filters?: FilterGroup | null
}

export interface DashboardWidgetParameters {
  title?: string
  interval?: string
  stacked?: boolean
  legend?: boolean
  distributed?: boolean
}
