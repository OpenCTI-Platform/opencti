import { Alert, Drawer, IconButton, ListItem, ListItemText, SxProps, Toolbar, Tooltip, Typography } from '@mui/material';
import React from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { useTheme } from '@mui/styles';
import { ContentCopy } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { renderWidgetIcon } from '../../../../utils/widget/widgetUtils';
import { MESSAGING$ } from '../../../../relay/environment';

export const EMAIL_TEMPLATE_SIDEBAR_WIDTH = 350;

const EmailTemplateAttributesSidebar = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const attributesOfTheUserTitle = t_i18n('Attributes of the user');
  const attributesOfThePlatformTitle = t_i18n('Attributes of the platform');
  const userAttributes = [
    { variableName: 'user.firstname', label: 'First name' },
    { variableName: 'user.lastname', label: 'Last name' },
    { variableName: 'user.name', label: 'Name' },
    { variableName: 'user.user_email', label: 'Email' },
    { variableName: 'user.api_token', label: 'API token' },
    { variableName: 'user.account_status', label: 'Status' },
    { variableName: 'user.objectOrganization', label: 'Organizations' },
    { variableName: 'user.account_lock_after_date', label: 'Expire Date' },
  ];
  const platformAttributes = [
    { variableName: 'settings.platform_url', label: 'Platform URL' },
  ];

  const copyAttributeToClipboard = async (varName: string) => {
    await navigator.clipboard.writeText(`$${varName}`);
    MESSAGING$.notifySuccess(t_i18n('Attribute copied to clipboard'));
  };

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
          <Typography variant="body2">
            {t_i18n('Use these variables in your template.')}
          </Typography>
        </Alert>
        <ListItem
          key={attributesOfTheUserTitle}
          value={attributesOfTheUserTitle}
          sx={{
            borderBottom: `1px solid ${theme.palette.divider}`,
            paddingRight: 1,
            paddingTop: 0,
            gap: 0,
            flexDirection: 'column',
            alignItems: 'stretch',
          }}
        >
          <div style={{ display: 'flex', flex: 1, alignItems: 'center', gap: theme.spacing(1) }}>
            <Tooltip title={'attribute'}>
              {renderWidgetIcon('attribute', 'small')}
            </Tooltip>

            <Typography style={{ fontStyle: 'italic', flex: 1 }} variant="body2">
              {attributesOfTheUserTitle}
            </Typography>

            <div style={{ height: 36 }} ></div>

          </div>

          <div style={{ paddingLeft: theme.spacing(3.5) }}>
            {userAttributes.map((column) => {
              return (
                <div
                  key={column.variableName}
                  style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}
                >
                  <ListItemText secondary={`$${column.variableName} (${column.label})`} />

                  <Tooltip title={t_i18n('Copy attribute name to clipboard')}>
                    <IconButton
                      aria-haspopup="true"
                      color="primary"
                      onClick={() => copyAttributeToClipboard(column.variableName ?? '')}
                    >
                      <ContentCopy fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </div>
              );
            })}
          </div>
        </ListItem>
        <ListItem
          key={attributesOfThePlatformTitle}
          value={attributesOfThePlatformTitle}
          sx={{
            borderBottom: `1px solid ${theme.palette.divider}`,
            paddingRight: 1,
            gap: 0,
            flexDirection: 'column',
            alignItems: 'stretch',
          }}
        >
          <div style={{ display: 'flex', flex: 1, alignItems: 'center', gap: theme.spacing(1) }}>
            <Tooltip title={'attribute'}>
              {renderWidgetIcon('attribute', 'small')}
            </Tooltip>

            <Typography style={{ fontStyle: 'italic', flex: 1 }} variant="body2">
              {attributesOfThePlatformTitle}
            </Typography>

            <div style={{ height: 36 }}>
            </div>
          </div>

          <div style={{ paddingLeft: theme.spacing(3.5) }}>
            {platformAttributes.map((column) => {
              return (
                <div
                  key={column.variableName}
                  style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}
                >
                  <ListItemText secondary={`$${column.variableName} (${column.label})`} />

                  <Tooltip title={t_i18n('Copy attribute name to clipboard')}>
                    <IconButton
                      aria-haspopup="true"
                      color="primary"
                      onClick={() => copyAttributeToClipboard(column.variableName ?? '')}
                    >
                      <ContentCopy fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </div>
              );
            })}
          </div>
        </ListItem>
      </Drawer>

    </>
  );
};

export default EmailTemplateAttributesSidebar;
