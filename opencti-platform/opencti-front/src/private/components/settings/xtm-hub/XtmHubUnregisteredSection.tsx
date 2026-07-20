import { MapOutlined, RocketLaunchOutlined, VideoLibraryOutlined, WidgetsOutlined } from '@mui/icons-material';
import { Button, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import React, { useContext } from 'react';
import { useFormatter } from 'src/components/i18n';
import type { Theme } from 'src/components/Theme';
import { UserContext } from 'src/utils/hooks/useAuth';
import XtmHubFeatureCard from './XtmHubFeatureCard';
import { getXtmHubLogo } from './xtm-hub.utils';

interface XtmHubUnregisteredSectionProps {
  onConnect?: () => void;
}

const XtmHubUnregisteredSection: React.FC<XtmHubUnregisteredSectionProps> = ({ onConnect }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { settings } = useContext(UserContext);
  const xtmHubLogo = getXtmHubLogo(theme);
  const hubUrl = settings?.platform_xtmhub_url ?? 'https://hub.filigran.io';

  const featurePrimaryColor = theme.palette.text.primary;
  const features = [
    {
      icon: (
        <RocketLaunchOutlined sx={{ fontSize: 20, color: featurePrimaryColor }} />
      ),
      label: t_i18n('XTM Platform free trial'),
    },
    {
      icon: (
        <WidgetsOutlined sx={{ fontSize: 20, color: featurePrimaryColor }} />
      ),
      label: t_i18n('Pre-built content'),
    },
    {
      icon: (
        <MapOutlined sx={{ fontSize: 20, color: featurePrimaryColor }} />
      ),
      label: t_i18n('XTM Platform Roadmap'),
    },
    {
      icon: (
        <VideoLibraryOutlined sx={{ fontSize: 20, color: featurePrimaryColor }} />
      ),
      label: t_i18n('Academy'),
    },
  ];

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
            {t_i18n('Extend and scale your OpenCTI experience')}
          </Typography>
          <Typography variant="body1">
            {t_i18n('Connect OpenCTI to XTM Hub to deploy pre-configured dashboards, integrations, and playbooks in one click, stay up to date with product news feeds, start free trials, and get more out of your XTM platform.')}
          </Typography>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: theme.spacing(2),
          }}
          >
            {features.map((feature) => (
              <XtmHubFeatureCard
                key={feature.label}
                icon={feature.icon}
                label={feature.label}
              />
            ))}
          </div>
        </div>

        <div style={{
          display: 'flex',
          justifyContent: 'flex-end',
          gap: theme.spacing(2),
          height: 36,
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
            {t_i18n('Explore XTM Hub')}
          </Button>
          <Button
            variant="contained"
            onClick={onConnect}
            disabled={!onConnect}
            sx={{
              textTransform: 'none',
              fontWeight: 600,
            }}
          >
            {t_i18n('Connect to XTM Hub')}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default XtmHubUnregisteredSection;
