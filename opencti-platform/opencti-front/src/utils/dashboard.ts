import { copyToClipboard } from './utils';
import { APP_BASE_PATH } from '../relay/environment';
import type { Widget } from './widget/widget';

export interface DashboardConfig {
  startDate?: string;
  endDate?: string;
  relativeDate?: string;
}

export interface DashboardManifest {
  config: DashboardConfig;
  widgets: Record<string, Widget>;
}

export const copyPublicLinkUrl = (t: (text: string) => string, uriKey: string) => {
  copyToClipboard(
    t,
    `${window.location.origin}${APP_BASE_PATH}/public/dashboard/${uriKey.toLowerCase()}`,
  );
};
