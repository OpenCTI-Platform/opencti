import type { Widget } from '../../../utils/widget/widget';
import { RootPrivateQuery$data } from '../../__generated__/RootPrivateQuery.graphql';

export type CustomViewsInfo = NonNullable<RootPrivateQuery$data['customViewsDisplayContext']>[number]['custom_views_info'];

export interface CustomViewManifestConfig {
  startDate?: string;
  endDate?: string;
  relativeDate?: string;
}

export interface CustomViewManifest {
  config?: CustomViewManifestConfig;
  widgets?: Record<string, Widget>;
}
