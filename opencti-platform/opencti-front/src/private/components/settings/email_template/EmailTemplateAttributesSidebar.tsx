import { Alert, Drawer, SxProps, Toolbar, Typography } from '@mui/material';
import React from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

export const EMAIL_TEMPLATE_SIDEBAR_WIDTH = 350;

const EmailTemplateAttributesSidebar = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  const paperStyle: SxProps = {
    '.MuiDrawer-paper': {
      width: EMAIL_TEMPLATE_SIDEBAR_WIDTH,
      padding: `${theme.spacing(2)} 0`,
      paddingTop: `calc(${theme.spacing(2)} +  ${settingsMessagesBannerHeight}px)`,
    },
  };

  return (
    <>
      <Drawer variant="permanent" anchor="right" sx={paperStyle}>
        <Toolbar />
        <Alert severity="info" variant="outlined" sx={{ margin: 2, marginTop: 0 }}>
          <Typography variant="body2" gutterBottom>
            {t_i18n('Use these variables in your template.')}
          </Typography>
        </Alert>
      </Drawer>

    </>
  );
};

export default EmailTemplateAttributesSidebar;
