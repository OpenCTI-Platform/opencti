import { useLocation } from 'react-router-dom';
import { useDropDownMenuState } from '../../../components/TabWithDropDownMenu';
import { useCustomViews } from './useCustomViews';

interface UseCustomViewTabsParams {
  /** Entity type being visited **/
  entityType: string;
  /** Original base path where the <Tabs> are displayed **/
  basePath: string;
}

export type CustomViewDisplayMode = 'none' | 'single' | 'dropdown';

interface UseCustomViewTabsResult {
  customViews: ReturnType<typeof useCustomViews>['customViews'];
  displayMode: CustomViewDisplayMode;
  dropDownMenuState: ReturnType<typeof useDropDownMenuState>;
  currentCustomViewTab: string | undefined;
}

const useCustomViewTabs = ({ basePath, entityType }: UseCustomViewTabsParams): UseCustomViewTabsResult => {
  const location = useLocation();
  const { customViews, getCurrentCustomViewTab } = useCustomViews(entityType);
  const currentCustomViewTab = getCurrentCustomViewTab(location.pathname, basePath);
  const dropDownMenuState = useDropDownMenuState();

  let displayMode: CustomViewDisplayMode = 'none';
  if (customViews.length === 1) displayMode = 'single';
  else if (customViews.length > 1) displayMode = 'dropdown';

  return {
    customViews,
    displayMode,
    dropDownMenuState,
    currentCustomViewTab,
  };
};

export default useCustomViewTabs;
