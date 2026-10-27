import React from 'react';
import { Link } from 'react-router';
import { Stack, Typography } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import { ArrowForwardOutlined } from '@mui/icons-material';
import { useHealthIssueDisplay, type HealthIssue } from '@components/integrations/deployed/IngestionHealthSummary';
import useHealthCheckMessage from '@components/data/connectors/useHealthCheckMessage';
import { useFormatter } from '../../../../components/i18n';
import { capitalizeFirstLetter } from '../../../../utils/String';
import { paperBorder } from '../paperSurface';

interface IngestionHealthTileBannerProps {
  issue: HealthIssue;
  // Where Review leads: the integration detail
  to: string;
}

// Strip on top of a deployed integration tile: critical = red / warning, degraded = orange / clock, both leading to Review.
const IngestionHealthTileBanner = ({ issue, to }: IngestionHealthTileBannerProps) => {
  const { t_i18n } = useFormatter();
  const { getHealthCheckMessage } = useHealthCheckMessage();
  const theme = useTheme();
  const { color, Icon } = useHealthIssueDisplay(issue.severity);
  return (
    <Stack
      component={Link}
      to={to}
      data-testid="integration-health-banner"
      className="integration-health-banner"
      direction="row"
      sx={{
        alignItems: 'center',
        gap: 1,
        color,
        textDecoration: 'none',
        padding: theme.spacing(1.25, 3),
        borderRadius: '4px 4px 0 0',
        border: `1px solid ${paperBorder(theme)}`,
        borderBottom: `2px solid ${color}`,
        backgroundColor: alpha(color, 0.12),
        transition: 'border-color 0.3s ease-in-out',
        fontSize: 13,
        fontWeight: 600,
      }}
    >
      <Icon sx={{ fontSize: 18 }} />
      <Typography noWrap sx={{ flex: 1, minWidth: 0, color: 'inherit', fontSize: 'inherit', fontWeight: 'inherit' }}>
        {issue.check ? getHealthCheckMessage(issue.check) : t_i18n(capitalizeFirstLetter(issue.severity))}
      </Typography>
      <Typography sx={{ color: 'inherit', fontSize: 'inherit', fontWeight: 'inherit', whiteSpace: 'nowrap' }}>
        {t_i18n('Review')}
      </Typography>
      <ArrowForwardOutlined sx={{ fontSize: 14 }} />
    </Stack>
  );
};

export default IngestionHealthTileBanner;
