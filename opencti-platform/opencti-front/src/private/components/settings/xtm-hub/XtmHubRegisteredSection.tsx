import { Button, Chip, Divider, Typography } from '@mui/material';
import { alpha } from '@mui/material/styles';
import { useTheme } from '@mui/styles';
import React, { useContext } from 'react';
import { useFormatter } from 'src/components/i18n';
import type { Theme } from 'src/components/Theme';
import { UserContext } from 'src/utils/hooks/useAuth';
import { getChipStyle, getXtmHubLogo } from './xtm-hub.utils';

interface XtmHubRegisteredSectionProps {
  registrationStatus: string;
  registrationDate: string | null | undefined;
  registrationUserName: string | null | undefined;
  onDisconnect?: () => void;
}

const XtmHubRegisteredSection: React.FC<XtmHubRegisteredSectionProps> = ({
  registrationStatus,
  registrationDate,
  registrationUserName,
  onDisconnect,
}) => {
  const { t_i18n, fldt } = useFormatter();
  const theme = useTheme<Theme>();
  const { settings } = useContext(UserContext);
  const xtmHubLogo = getXtmHubLogo(theme);
  const hubUrl = settings?.platform_xtmhub_url ?? 'https://hub.filigran.io';

  const isConnected = registrationStatus === 'registered';
  const statusLabel = isConnected ? t_i18n('Connected') : t_i18n('Connectivity lost');
  const statusBg = isConnected
    ? alpha(theme.palette.success.main ?? '', 0.2)
    : alpha(theme.palette.error.main ?? '', 0.2);
  const connectionDate = registrationDate ? fldt(registrationDate) : '-';
  const connectedBy = registrationUserName ?? '-';

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: theme.spacing(2),
    }}
    >
      <img src={xtmHubLogo} alt="XTM Hub" style={{ height: 35 }} />

      <div style={{
        display: 'flex',
        flexDirection: 'column',
        gap: theme.spacing(4),
        width: '100%',
      }}
      >
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          gap: theme.spacing(2),
        }}
        >
          <Typography variant="h5">
            {t_i18n('Experiment valuable threat management resources in the XTM Hub')}
          </Typography>

          <div>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: `${theme.spacing(1.5)} 0`,
            }}
            >
              <Typography variant="body2" color="text.secondary">{t_i18n('Connection status')}</Typography>
              <Chip
                sx={{
                  ...getChipStyle(theme),
                  backgroundColor: statusBg,
                }}
                label={statusLabel}
              />
            </div>
            <Divider />
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: `${theme.spacing(1.5)} 0`,
            }}
            >
              <Typography variant="body2" color="text.secondary">{t_i18n('Connection date')}</Typography>
              <Chip
                sx={{
                  ...getChipStyle(theme),
                  backgroundColor: alpha(theme.palette.primary.main ?? '', 0.2),
                }}
                label={connectionDate}
              />
            </div>
            <Divider />
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: `${theme.spacing(1.5)} 0`,
            }}
            >
              <Typography variant="body2" color="text.secondary">{t_i18n('Connected by')}</Typography>
              <Typography variant="body2" color="text.primary">{connectedBy}</Typography>
            </div>
            <Divider />
          </div>
        </div>

        <div style={{
          display: 'flex',
          justifyContent: 'flex-end',
          gap: theme.spacing(2),
        }}
        >
          <Button
            variant="outlined"
            component="a"
            href={hubUrl}
            target="_blank"
            rel="noreferrer"
            sx={{
              textTransform: 'none',
              fontWeight: 600,
              borderColor: theme.palette.border.primary,
              '&:hover': { borderColor: theme.palette.border.primary },
            }}
          >
            {t_i18n('Go to the Hub')}
          </Button>
          <Button
            variant="outlined"
            color="error"
            onClick={onDisconnect}
            disabled={!onDisconnect}
            sx={{
              textTransform: 'none',
              fontWeight: 600,
            }}
          >
            {t_i18n('Disconnect XTM Hub')}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default XtmHubRegisteredSection;
