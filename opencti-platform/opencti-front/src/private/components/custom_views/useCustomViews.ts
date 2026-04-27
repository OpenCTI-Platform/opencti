import { getCurrentTab } from '../../../utils/utils';
import type { CustomView } from './CustomViews-types';
import { useCustomViewsData } from './useCustomViewsData';

export const CUSTOM_VIEW_TAB_VALUE = 'custom-view';

function matchPath(customViews: CustomView[]) {
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
  const { customViews } = useCustomViewsData(entityType);

  if (customViews.length === 0) {
    return NO_CUSTOM_VIEWS;
  }

  const getCurrentCustomViewTab = matchPath(customViews);
  return { customViews, getCurrentCustomViewTab };
};
