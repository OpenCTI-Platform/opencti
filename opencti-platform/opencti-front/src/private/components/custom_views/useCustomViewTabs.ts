import { useLocation } from 'react-router-dom';
import { useDropDownMenuState } from '../../../components/TabWithDropDownMenu';
import { getCurrentTab } from '../../../utils/utils';
import { useCustomViews } from './useCustomViews';
import { CustomViewsPreloadedQuery } from './CustomViewsQueryLoader';

interface UseCustomViewTabsParams {
  /** Original base path where the <Tabs> are displayed **/
  basePath: string;
  queryRef: CustomViewsPreloadedQuery;
}

export interface CustomViewDisplayMode {
  default: boolean;
  others: 'none' | 'single' | 'dropdown';
}

interface UseCustomViewTabsResult {
  defaultCustomView: ReturnType<typeof useCustomViews>['customViews'][number] | undefined;
  otherCustomViews: ReturnType<typeof useCustomViews>['customViews'];
  displayMode: CustomViewDisplayMode;
  dropDownMenuState: ReturnType<typeof useDropDownMenuState>;
  currentCustomViewTab: string | undefined;
  currentCustomViewMenuItem: string | undefined;
}

const useCustomViewTabs = ({ basePath, queryRef }: UseCustomViewTabsParams): UseCustomViewTabsResult => {
  const location = useLocation();
  const { customViews, getCurrentCustomViewTab } = useCustomViews(queryRef);
  const currentCustomViewTab = getCurrentCustomViewTab(location.pathname, basePath);
  const currentCustomViewMenuItem = getCurrentTab(location.pathname, basePath);
  const dropDownMenuState = useDropDownMenuState();

  const defaultCustomView = customViews.find(({ default: def }) => def);
  const hasDefault = !!defaultCustomView;

  let othersDisplayMode: CustomViewDisplayMode['others'] = 'none';
  const minCountForOthers = hasDefault ? 2 : 1;
  if (customViews.length === minCountForOthers) {
    othersDisplayMode = 'single';
  } else if (customViews.length > minCountForOthers) {
    othersDisplayMode = 'dropdown';
  }
  const displayMode: CustomViewDisplayMode = {
    default: hasDefault,
    others: othersDisplayMode,
  };
  const otherCustomViews = hasDefault ? customViews.filter((c) => !c.default) : customViews;

  return {
    defaultCustomView,
    otherCustomViews,
    displayMode,
    dropDownMenuState,
    currentCustomViewTab,
    currentCustomViewMenuItem,
  };
};

export default useCustomViewTabs;
