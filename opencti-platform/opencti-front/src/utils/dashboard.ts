import { FilterGroup } from './filters/filtersHelpers-types';
import { copyToClipboard } from './utils';
import { APP_BASE_PATH } from '../relay/environment';

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

export const copyPublicLinkUrl = (t: (text: string) => string, uriKey: string) => {
  copyToClipboard(
    t,
    `${window.location.origin}${APP_BASE_PATH}/public/dashboard/${uriKey.toLowerCase()}`,
  );
};
