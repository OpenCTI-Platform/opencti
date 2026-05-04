import type { Widget } from '../../../utils/widget/widget';
import { useCustomViews_data$data } from './__generated__/useCustomViews_data.graphql';

export type CustomView = NonNullable<useCustomViews_data$data['customViews']>['edges'][number]['node'];

export interface CustomViewManifestConfig {
  startDate?: string;
  endDate?: string;
  relativeDate?: string;
}

export interface CustomViewManifest {
  config?: CustomViewManifestConfig;
  widgets?: Record<string, Widget>;
}
