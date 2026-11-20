import { Alert, Drawer, ListItem, ListItemText, SxProps, Toolbar, Tooltip, Typography } from '@mui/material';
import { IconButton } from '@filigran/design-system';
import React from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { useTheme } from '@mui/material/styles';
import { ContentCopy } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { renderWidgetIcon } from '../../../../utils/widget/widgetUtils';
import { MESSAGING$ } from '../../../../relay/environment';
import useHelper from '../../../../utils/hooks/useHelper';

export const EMAIL_TEMPLATE_SIDEBAR_WIDTH = 350;

type TemplateAttribute = { variableName: string; label: string };

const userAttributes: TemplateAttribute[] = [
  { variableName: 'user.firstname', label: 'First name' },
  { variableName: 'user.lastname', label: 'Last name' },
  { variableName: 'user.name', label: 'Name' },
  { variableName: 'user.token_user', label: 'New generated token' },
  { variableName: 'user.user_email', label: 'Email' },
  { variableName: 'user.account_status', label: 'Status' },
  { variableName: 'user.objectOrganization', label: 'Organizations' },
  { variableName: 'user.account_lock_after_date', label: 'Expire Date' },
];
const platformAttributes: TemplateAttribute[] = [
  { variableName: 'settings.platform_url', label: 'Platform URL' },
];
// The account locked by the local authentication lockout, for the email sent to the administrators: $user is the recipient
const lockedUserAttributes: TemplateAttribute[] = [
  { variableName: 'locked_user.firstname', label: 'First name' },
  { variableName: 'locked_user.lastname', label: 'Last name' },
  { variableName: 'locked_user.name', label: 'Name' },
  { variableName: 'locked_user.user_email', label: 'Email' },
];
const lockAttributes: TemplateAttribute[] = [
  { variableName: 'lock.date', label: 'Date of the lock' },
  { variableName: 'lock.attempts', label: 'Failed attempts' },
  { variableName: 'lock.type', label: 'Temporary or permanent' },
  { variableName: 'lock.end_date', label: 'End of a temporary lock' },
  { variableName: 'lock.unlock', label: 'When the account is unlocked' },
];

const AttributesSection = ({ title, attributes, isFirst = false }: { title: string; attributes: TemplateAttribute[]; isFirst?: boolean }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const copyAttributeToClipboard = async (varName: string) => {
    await navigator.clipboard.writeText(`$${varName}`);
    MESSAGING$.notifySuccess(t_i18n('Attribute copied to clipboard'));
  };

  return (
    <ListItem
      value={title}
      sx={{
        borderBottom: `1px solid ${theme.palette.divider}`,
        paddingRight: 1,
        ...(isFirst && { paddingTop: 0 }),
        gap: 0,
        flexDirection: 'column',
        alignItems: 'stretch',
      }}
    >
      <div style={{ display: 'flex', flex: 1, alignItems: 'center', gap: theme.spacing(1) }}>
        <Tooltip title="attribute">
          {renderWidgetIcon('attribute', 'small')}
        </Tooltip>

        <Typography style={{ fontStyle: 'italic', flex: 1 }} variant="body2">
          {title}
        </Typography>

        <div style={{ height: 36 }}></div>
      </div>

      <div style={{ paddingLeft: theme.spacing(3.5) }}>
        {attributes.map((column) => {
          return (
            <div
              key={column.variableName}
              style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}
            >
              <ListItemText secondary={`$${column.variableName} (${column.label})`} />

              <Tooltip title={t_i18n('Copy attribute name to clipboard')}>
                <IconButton
                  variant="default"
                  priority="tertiary"
                  aria-label={t_i18n('Copy attribute name to clipboard')}
                  aria-haspopup="true"
                  onClick={() => copyAttributeToClipboard(column.variableName)}
                  icon={<ContentCopy fontSize="small" />}
                />
              </Tooltip>
            </div>
          );
        })}
      </div>
    </ListItem>
  );
};

const EmailTemplateAttributesSidebar = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  const paperStyle: SxProps = {
    '.MuiDrawer-paper': {
      width: EMAIL_TEMPLATE_SIDEBAR_WIDTH,
      padding: `${theme.spacing(2)} 0`,
      paddingTop: `calc(${theme.spacing(2)} +  ${settingsMessagesBannerHeight}px)`,
      zIndex: theme.zIndex.appBar - 1,
    },
  };

  return (
    <>
      <Drawer
        variant="permanent"
        anchor="right"
        sx={paperStyle}
      >
        <Toolbar />
        <Alert severity="info" variant="outlined" sx={{ margin: 2, marginTop: 0 }}>
          <Typography variant="body2">
            {t_i18n('Use these variables in your template.')}
          </Typography>
        </Alert>
        <AttributesSection title={t_i18n('Attributes of the user')} attributes={userAttributes} isFirst />
        <AttributesSection title={t_i18n('Attributes of the platform')} attributes={platformAttributes} />
        {isFeatureEnable('LOCAL_AUTH_LOCKOUT') && (
          <>
            <AttributesSection title={t_i18n('Attributes of the locked user')} attributes={lockedUserAttributes} />
            <AttributesSection title={t_i18n('Attributes of the lock')} attributes={lockAttributes} />
          </>
        )}
      </Drawer>

    </>
  );
};

export default EmailTemplateAttributesSidebar;
