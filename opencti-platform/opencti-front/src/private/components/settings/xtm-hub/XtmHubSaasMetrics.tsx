import React, { ReactNode } from 'react';
import Box from '@mui/material/Box';
import { alpha, useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';
import { NorthEastOutlined, ScheduleOutlined, ShowChartOutlined, StorageOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

interface MetricHighlightProps {
  icon: ReactNode;
  title: string;
  description: string;
  accent: string;
}

const MetricHighlight = ({ icon, title, description, accent }: MetricHighlightProps) => (
  <Box sx={{
    display: 'flex',
    alignItems: 'flex-start',
    gap: 1,
  }}
  >
    <Box sx={{
      display: 'flex',
      color: accent,
      '& svg': { fontSize: 16 },
    }}
    >
      {icon}
    </Box>
    <Box sx={{ minWidth: 0 }}>
      <Text variant="content-compact-bold">{title}</Text>
      <Text variant="content-caption" as="p" className="text-default-secondary">{description}</Text>
    </Box>
  </Box>
);

interface XtmHubSaasMetricsProps {
  metricsUrl: string;
}

/**
 * Pitch shown to a platform whose XTM Hub registration runs on the SaaS
 * commercial model: its subscription, contract and usage metrics live on the
 * Hub. Aligned with the OpenAEV Filigran Experience screen.
 */
const XtmHubSaasMetrics = ({ metricsUrl }: XtmHubSaasMetricsProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const accent = theme.palette.primary.main ?? '#ffffff';
  const hairline = `1px solid ${alpha(theme.palette.text?.primary ?? '#ffffff', 0.08)}`;

  return (
    <Box
      component="section"
      data-testid="xtm-hub-saas-metrics"
      sx={{
        display: 'flex',
        flexDirection: 'column',
        gap: 1.5,
        padding: 2,
        borderRadius: 1,
        border: `1px solid ${alpha(accent, 0.3)}`,
        background: alpha(accent, 0.06),
      }}
    >
      <div>
        <Text
          variant="content-caption"
          as="p"
          className="uppercase"
          // Same overline as the ExperienceCard header: the library ships no letter-spacing scale.
          style={{
            color: accent,
            letterSpacing: '0.1em',
          }}
        >
          {t_i18n('New · SaaS metrics')}
        </Text>
        <Text variant="content-base-bold" as="h3" style={{ margin: 0 }}>
          {t_i18n('Your OpenCTI, by the numbers')}
        </Text>
      </div>
      <Text variant="content-base" className="text-default-secondary">
        {t_i18n('Your platform runs in the Filigran cloud. XTM Hub shows you the whole picture in one place: what you subscribed to, how much storage your intelligence takes, the uptime you are guaranteed and how much time is left on your contract.')}
      </Text>
      <Box sx={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
        gap: 2,
      }}
      >
        <MetricHighlight
          accent={accent}
          icon={<ShowChartOutlined />}
          title={t_i18n('Your plan')}
          description={t_i18n('Know exactly what you are running on')}
        />
        <MetricHighlight
          accent={accent}
          icon={<ScheduleOutlined />}
          title={t_i18n('Contract countdown')}
          description={t_i18n('Days left before renewal, no surprises')}
        />
        <MetricHighlight
          accent={accent}
          icon={<StorageOutlined />}
          title={t_i18n('Storage & uptime')}
          description={t_i18n('Database space used and the SLA you can count on')}
        />
      </Box>
      <Box sx={{
        display: 'flex',
        justifyContent: 'flex-end',
        paddingTop: 1.5,
        borderTop: hairline,
      }}
      >
        <Button
          component="a"
          href={metricsUrl}
          target="_blank"
          rel="noopener noreferrer"
          endIcon={<NorthEastOutlined />}
        >
          {t_i18n('See my OpenCTI metrics')}
        </Button>
      </Box>
    </Box>
  );
};

export default XtmHubSaasMetrics;
