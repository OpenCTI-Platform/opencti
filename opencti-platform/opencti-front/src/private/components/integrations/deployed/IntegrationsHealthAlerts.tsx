import React from 'react';
import { Link } from 'react-router';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import IngestionHealthBanner from '@components/data/connectors/IngestionHealthBanner';
import { type HealthIssue } from '@components/integrations/deployed/IngestionHealthSummary';
import useHealthCheckMessage from '@components/data/connectors/useHealthCheckMessage';
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
  const { getHealthCheckMessage } = useHealthCheckMessage();
  const theme = useTheme();
  const { isFeatureEnable } = useHelper();
  if (!isFeatureEnable('INGESTION_HEALTH')) return null;

  const alerts = (['critical', 'degraded'] as const).flatMap((severity) => {
    const affected = items.filter((item) => item.healthIssue?.severity === severity);
    if (affected.length === 0) return [];
    const count = affected.length;
    const isSingleAlert = count === 1;
    const isCritical = severity === 'critical';
    let title: string;
    if (isCritical) {
      title = isSingleAlert ? t_i18n('1 integration is not working') : t_i18n('{count} integrations are not working', { values: { count } });
    } else {
      title = isSingleAlert ? t_i18n('1 integration is degraded') : t_i18n('{count} integrations are degraded', { values: { count } });
    }
    const names = affected.slice(0, MAX_NAMES).map((item) => item.name).join(', ');
    const more = count > MAX_NAMES ? ` +${count - MAX_NAMES}` : '';
    // A single integration says what is wrong with it
    const issue = isSingleAlert ? affected[0].healthIssue : null;
    const message = issue?.check ? getHealthCheckMessage(issue.check) : null;
    const label = isSingleAlert ? t_i18n('Review') : t_i18n('See all');
    return [(
      <IngestionHealthBanner
        key={severity}
        data-testid={`integrations-health-alert-${severity}`}
        severity={severity}
        title={title}
        lines={[`${names}${more}${message ? ` — ${message}` : ''}`]}
        action={isSingleAlert ? (
          <Button variant="secondary" size="small" component={Link} to={affected[0].detailUrl}>{label}</Button>
        ) : (
          <Button variant="secondary" size="small" onClick={() => onShowIssue(severity)}>{label}</Button>
        )}
      />
    )];
  });

  if (alerts.length === 0) return null;
  return <div className="flex flex-col" style={{ gap: theme.spacing(1) }}>{alerts}</div>;
};

export default IntegrationsHealthAlerts;
