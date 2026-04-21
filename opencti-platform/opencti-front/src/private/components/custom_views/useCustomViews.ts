import { getCurrentTab } from '../../../utils/utils';
import useAuth from '../../../utils/hooks/useAuth';
import type { CustomViewsInfo } from './CustomViews-types';

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

export const useCustomViews = (targetEntityType: string) => {
  const { customViews: customViewsContext } = useAuth();
  const customViewsContextForType = customViewsContext.find(({ entityType }) => entityType === targetEntityType);
  if (!customViewsContextForType) {
    return NO_CUSTOM_VIEWS;
  }
  const customViews = customViewsContextForType.customViews ?? [];
  const getCurrentCustomViewTab = matchPath(customViews);
  const sortedCustomViews = [...customViews].sort(
    (lhs, rhs) => lhs.name.localeCompare(rhs.name),
  );
  return {
    customViews: sortedCustomViews,
    getCurrentCustomViewTab,
  };
};
