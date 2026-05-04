import { Link } from 'react-router-dom';
import Tab, { TabProps } from '@mui/material/Tab';
import type { CustomViewDisplayMode } from './useCustomViewTabs';
import { useCustomViews } from './useCustomViews';
import { TabWithDropDownMenu, useDropDownMenuState } from '../../../components/TabWithDropDownMenu';
import { useFormatter } from '../../../components/i18n';

type OtherCustomViewsTabProps = {
  displayMode: CustomViewDisplayMode;
  otherCustomViews: ReturnType<typeof useCustomViews>['customViews'];
  dropDownMenuState: ReturnType<typeof useDropDownMenuState>;
  value: string;
} & TabProps<'a'> & TabProps<'div'>;

export const OtherCustomViewsTab = ({ otherCustomViews: customViews, displayMode, dropDownMenuState, value, ...tabProps }: OtherCustomViewsTabProps) => {
  const { t_i18n } = useFormatter();
  if (displayMode.others === 'single') {
    return (
      <Tab
        {...tabProps}
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

  if (displayMode.others === 'dropdown') {
    return (
      <TabWithDropDownMenu
        {...tabProps}
        value={value}
        label={t_i18n('Custom view')}
        isOpen={dropDownMenuState.isOpen}
        onOpen={dropDownMenuState.onOpen}
      />
    );
  }

  return null;
};

type DefaultCustomViewTabProps = {
  value: string;
  displayMode: CustomViewDisplayMode;
  defaultCustomView: ReturnType<typeof useCustomViews>['customViews'][number] | undefined;
} & TabProps<'a'> & TabProps<'div'>;

export const DefaultCustomViewTab = ({ value, displayMode, defaultCustomView, ...tabProps }: DefaultCustomViewTabProps) => {
  if (!displayMode.default) {
    return null;
  }
  if (!defaultCustomView) {
    return null;
  }
  return (
    <Tab
      {...tabProps}
      key="default-custom-view"
      component={Link}
      to={defaultCustomView.path}
      value={value}
      label={defaultCustomView.name}
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
};
