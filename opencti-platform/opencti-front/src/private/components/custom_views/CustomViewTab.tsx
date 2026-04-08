import { Link } from 'react-router-dom';
import Tab from '@mui/material/Tab';
import type { CustomViewDisplayMode } from './useCustomViewTabs';
import { useCustomViews } from './useCustomViews';
import { TabWithDropDownMenu, useDropDownMenuState } from '../../../components/TabWithDropDownMenu';
import { useFormatter } from '../../../components/i18n';

interface CustomViewTabProps {
  displayMode: CustomViewDisplayMode;
  customViews: ReturnType<typeof useCustomViews>['customViews'];
  dropDownMenuState: ReturnType<typeof useDropDownMenuState>;
  value: string;
}

const CustomViewTab = ({ customViews, displayMode, dropDownMenuState, value }: CustomViewTabProps) => {
  const { t_i18n } = useFormatter();
  if (displayMode === 'single') {
    return (
      <Tab
        component={Link}
        to={customViews[0].path}
        value={value}
        label={customViews[0].name}
        sx={{
        // Override the theme/global rule set to have all
        // tabs in first-letter-capitalized case, to display
        // exactly what customers want.
          textTransform: 'none',
          '&::first-letter': {
            textTransform: 'none',
          },
        }}
      />
    );
  }

  if (displayMode === 'dropdown') {
    return (
      <TabWithDropDownMenu
        value={value}
        label={t_i18n('Custom view')}
        isOpen={dropDownMenuState.isOpen}
        onOpen={dropDownMenuState.onOpen}
      />
    );
  }

  return null;
};

export default CustomViewTab;
