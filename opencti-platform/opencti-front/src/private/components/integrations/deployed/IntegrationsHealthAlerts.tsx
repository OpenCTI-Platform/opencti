import React from 'react';
import { Link } from 'react-router';
import { Stack } from '@mui/material';
import { Alert } from '@filigran/design-system';
import Button from '@common/button/Button';
import type { HealthIssue } from '@components/integrations/deployed/IngestionHealthSummary';
import type { DeployedIntegrationItem } from '@components/integrations/deployed/useDeployedIntegrations';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';

const MAX_NAMES = 3;

interface IntegrationsHealthAlertsProps {
  items: DeployedIntegrationItem[];
  // Narrows the list to the integrations in that health issue
  onShowIssue: (severity: HealthIssue['severity']) => void;
}

// One alert per health issue (critical, then degraded) summarizing the deployed integrations concerned.
const IntegrationsHealthAlerts = ({ items, onShowIssue }: IntegrationsHealthAlertsProps) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  if (!isFeatureEnable('INGESTION_HEALTH')) return null;

  const alerts = (['critical', 'degraded'] as const).flatMap((severity) => {
    const affected = items.filter((item) => item.healthIssue?.severity === severity);
    if (affected.length === 0) return [];
    const count = affected.length;
    const isCritical = severity === 'critical';
    let title: string;
    if (isCritical) {
      title = count === 1 ? t_i18n('1 integration is not working') : t_i18n('{count} integrations are not working', { values: { count } });
    } else {
      title = count === 1 ? t_i18n('1 integration is degraded') : t_i18n('{count} integrations are degraded', { values: { count } });
    }
    const names = affected.slice(0, MAX_NAMES).map((item) => item.name).join(', ');
    const more = count > MAX_NAMES ? ` +${count - MAX_NAMES}` : '';
    // A single integration says what is wrong with it
    const message = count === 1 ? affected[0].healthIssue?.message : null;
    const label = isCritical ? t_i18n('Fix') : t_i18n('Review');
    return [(
      <Alert
        key={severity}
        data-testid={`integrations-health-alert-${severity}`}
        severity={isCritical ? 'error' : 'warning'}
        title={title}
        description={`${names}${more}${message ? ` — ${message}` : ''}`}
        action={count === 1 ? (
          <Button variant="secondary" size="small" component={Link} to={affected[0].detailUrl}>{label}</Button>
        ) : (
          <Button variant="secondary" size="small" onClick={() => onShowIssue(severity)}>{label}</Button>
        )}
      />
    )];
  });

  if (alerts.length === 0) return null;
  return (
    <Stack
      sx={{
        gap: 1,
        // The design system ships no CSS reset: the legacy page leaves the default margins of the paragraphs of the Alert
        '& p': { margin: 0 },
        // More room than the Alert default, and the icon centered on the whole banner instead of on the title line
        '& [role]': { padding: 2 },
        '& [role] > div:first-of-type': { alignItems: 'center' },
      }}
    >
      {alerts}
    </Stack>
  );
};

export default IntegrationsHealthAlerts;
