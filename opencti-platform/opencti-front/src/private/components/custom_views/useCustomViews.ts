import { getCurrentTab } from '../../../utils/utils';
import useAuth from '../../../utils/hooks/useAuth';
import useHelper from '../../../utils/hooks/useHelper';
import { RootPrivateQuery$data } from '../../__generated__/RootPrivateQuery.graphql';

type CustomViewsInfo = NonNullable<RootPrivateQuery$data['customViewsDisplayContext']>[number]['custom_views_info'];

export const CUSTOM_VIEW_TAB_VALUE = 'custom-view';

function matchPath(customViews: CustomViewsInfo) {
  return (fullPath: string, basePath: string) => {
    const current = getCurrentTab(fullPath, basePath);
    if (customViews.find(({ path }) => path === current)) {
      return CUSTOM_VIEW_TAB_VALUE;
    }
    return undefined;
  };
}

const NO_CUSTOM_VIEWS = {
  customViews: [],
  getCurrentCustomViewTab: () => undefined,
};

export const useCustomViews = (entityType: string) => {
  const { isFeatureEnable } = useHelper();
  const isCustomViewFeatureEnabled = isFeatureEnable('CUSTOM_VIEW');
  const { customViews: customViewsContext } = useAuth();
  if (!isCustomViewFeatureEnabled) {
    return NO_CUSTOM_VIEWS;
  }
  const customViewsContextForType = customViewsContext.find(({ entity_type }) => entity_type === entityType);
  if (!customViewsContextForType) {
    return NO_CUSTOM_VIEWS;
  }
  const customViews = customViewsContextForType.custom_views_info ?? [];
  const getCurrentCustomViewTab = matchPath(customViews);
  return {
    customViews,
    getCurrentCustomViewTab,
  };
};
