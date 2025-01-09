import { Drawer, Toolbar, SxProps } from '@mui/material';
import React from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';

export const FINTEL_TEMPLATE_SIDEBAR_WIDTH = 350;

const FintelTemplateSidebar = () => {
  const theme = useTheme<Theme>();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  const paperStyle: SxProps = {
    '.MuiDrawer-paper': {
      width: FINTEL_TEMPLATE_SIDEBAR_WIDTH,
      padding: theme.spacing(2),
      marginTop: `${settingsMessagesBannerHeight}px`,
    },
  };

  return (
    <Drawer variant="permanent" anchor="right" sx={paperStyle}>
      <Toolbar />
      space for widgets
    </Drawer>
  );
};

export default FintelTemplateSidebar;
