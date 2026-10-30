import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import IngestionHealthBanner from '@components/data/connectors/IngestionHealthBanner';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import type { ConnectorHealthAlerts_ingestionHealth$key } from './__generated__/ConnectorHealthAlerts_ingestionHealth.graphql';

const connectorHealthAlertsFragment = graphql`
  fragment ConnectorHealthAlerts_ingestionHealth on IngestionHealth {
    status
    status_since
    healthChecks {
      health_check_code
      health_check_message
      health_check_kind
      health_check_severity
    }
  }
`;

interface HealthAlertProps {
  severity: 'critical' | 'degraded';
  messages: string[];
  // Since when the source has this status: only known for the severity of its status
  since: string | null;
  subject: 'connector' | 'feed';
}

// One banner per severity: the first issue is always shown, the others are folded behind a button
const HealthAlert = ({ severity, messages, since, subject }: HealthAlertProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const [expanded, setExpanded] = useState(false);
  const isCritical = severity === 'critical';
  const [first, ...others] = messages;
  const date = since ? nsdt(since) : '';
  let title: string;
  if (subject === 'feed') {
    if (isCritical) {
      title = since ? t_i18n('This feed is not working since {date}', { values: { date } }) : t_i18n('This feed is not working');
    } else {
      title = since ? t_i18n('This feed is degraded since {date}', { values: { date } }) : t_i18n('This feed is degraded');
    }
  } else if (isCritical) {
    title = since ? t_i18n('This connector is not working since {date}', { values: { date } }) : t_i18n('This connector is not working');
  } else {
    title = since ? t_i18n('This connector is degraded since {date}', { values: { date } }) : t_i18n('This connector is degraded');
  }
  return (
    <IngestionHealthBanner
      data-testid={`connector-health-alert-${severity}`}
      severity={severity}
      title={title}
      lines={[first, ...(expanded ? others : [])].map((message) => (others.length > 0 ? `- ${message}` : message))}
      action={others.length > 0 && (
        <Button variant="secondary" size="small" onClick={() => setExpanded((value) => !value)}>
          {expanded ? t_i18n('Show less') : t_i18n('Show {count} more', { values: { count: others.length } })}
        </Button>
      )}
    />
  );
};

interface ConnectorHealthAlertsProps {
  ingestionHealth?: ConnectorHealthAlerts_ingestionHealth$key | null;
  // Wording of the banner: connector pages by default, feeds and synchronizers use 'feed'
  subject?: 'connector' | 'feed';
}

// Health issues of one connector or feed, split by severity (critical, then degraded)
const ConnectorHealthAlerts = ({ ingestionHealth, subject = 'connector' }: ConnectorHealthAlertsProps) => {
  const theme = useTheme();
  const { isFeatureEnable } = useHelper();
  const data = useFragment(connectorHealthAlertsFragment, ingestionHealth ?? null);
  // Nothing to flag: not evaluated yet, healthy or unknown. The checks of an unknown status are not issues of this platform version
  if (!isFeatureEnable('INGESTION_HEALTH') || !data || (data.status !== 'critical' && data.status !== 'degraded')) return null;

  // Same rule as the backend status: only a blocking runtime check is critical
  const critical: string[] = [];
  const degraded: string[] = [];
  data.healthChecks.forEach((check) => {
    const isCritical = check.health_check_kind === 'runtime' && check.health_check_severity === 'blocking';
    (isCritical ? critical : degraded).push(check.health_check_message ?? check.health_check_code);
  });
  if (critical.length === 0 && degraded.length === 0) return null;

  return (
    <div className="flex flex-col" style={{ gap: theme.spacing(1), marginBottom: theme.spacing(2) }}>
      {critical.length > 0 && <HealthAlert severity="critical" messages={critical} since={data.status === 'critical' ? data.status_since : null} subject={subject} />}
      {degraded.length > 0 && <HealthAlert severity="degraded" messages={degraded} since={data.status === 'degraded' ? data.status_since : null} subject={subject} />}
    </div>
  );
};

export default ConnectorHealthAlerts;
