import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Stack } from '@mui/material';
import { Alert } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import type { ConnectorHealthAlerts_ingestionHealth$key } from './__generated__/ConnectorHealthAlerts_ingestionHealth.graphql';

const connectorHealthAlertsFragment = graphql`
  fragment ConnectorHealthAlerts_ingestionHealth on IngestionHealth {
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
}

// One banner per severity: the first issue is always shown, the others are folded behind a button
const HealthAlert = ({ severity, messages }: HealthAlertProps) => {
  const { t_i18n } = useFormatter();
  const [expanded, setExpanded] = useState(false);
  const isCritical = severity === 'critical';
  const [first, ...others] = messages;
  return (
    <Alert
      data-testid={`connector-health-alert-${severity}`}
      severity={isCritical ? 'error' : 'warning'}
      title={`${isCritical ? t_i18n('This connector is not working') : t_i18n('This connector is degraded')}:`}
      // The check is the key information: same typography as the title (the description is a <p>, hence spans)
      description={[first, ...(expanded ? others : [])].map((message, index) => (
        <span key={`${index}-${message}`} className="title-xs" style={{ display: 'block' }}>{others.length > 0 ? `- ${message}` : message}</span>
      ))}
      action={others.length > 0 && (
        <Button variant="secondary" size="small" onClick={() => setExpanded((value) => !value)}>
          {expanded ? t_i18n('Show less') : t_i18n('Show {count} more', { values: { count: others.length } })}
        </Button>
      )}
    />
  );
};

// Health issues of one connector, split by severity (critical, then degraded)
const ConnectorHealthAlerts = ({ ingestionHealth }: { ingestionHealth?: ConnectorHealthAlerts_ingestionHealth$key | null }) => {
  const { isFeatureEnable } = useHelper();
  const data = useFragment(connectorHealthAlertsFragment, ingestionHealth ?? null);
  if (!isFeatureEnable('INGESTION_HEALTH') || !data) return null;

  // Same rule as the backend status: only a blocking runtime check is critical
  const critical: string[] = [];
  const degraded: string[] = [];
  data.healthChecks.forEach((check) => {
    const isCritical = check.health_check_kind === 'runtime' && check.health_check_severity === 'blocking';
    (isCritical ? critical : degraded).push(check.health_check_message ?? check.health_check_code);
  });
  if (critical.length === 0 && degraded.length === 0) return null;

  return (
    <Stack
      gap={1}
      sx={{
        marginBottom: 2,
        '& p': { margin: 0 },
        // No bold: title and checks share the regular weight
        '& [role] p, & [role] p span': { fontWeight: 'normal' },
        '& [role]': { padding: 2 },
        '& [role] > div:first-of-type': { alignItems: 'center' },
      }}
    >
      {critical.length > 0 && <HealthAlert severity="critical" messages={critical} />}
      {degraded.length > 0 && <HealthAlert severity="degraded" messages={degraded} />}
    </Stack>
  );
};

export default ConnectorHealthAlerts;
