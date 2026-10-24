import { graphql, readInlineData } from 'react-relay';
import { AccessTimeOutlined, WarningAmberOutlined } from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';
import { useIngestionHealthColor } from '@components/data/connectors/IngestionHealthChip';
import type { IngestionHealthSummary_ingestionHealth$key } from './__generated__/IngestionHealthSummary_ingestionHealth.graphql';

// Read as plain data, outside of any component: the integrations page aggregates the health of every item.
// Spread next to IngestionHealthChip_ingestionHealth in the queries feeding the deployed integrations.
const ingestionHealthSummaryFragment = graphql`
  fragment IngestionHealthSummary_ingestionHealth on IngestionHealth @inline {
    status
    healthChecks {
      health_check_code
      health_check_message
    }
  }
`;

export interface HealthIssue {
  severity: 'critical' | 'degraded';
  // First failing check; null when the status carries none
  message: string | null;
}

// Color and icon every marker of a health issue shares: critical = red / warning, degraded = orange / clock
export const useHealthIssueDisplay = (severity: HealthIssue['severity']): { color: string; Icon: SvgIconComponent } => {
  const healthColor = useIngestionHealthColor();
  // Same colors as every other health marker; the theme colors are optional in its type
  const color = healthColor(severity) ?? 'inherit';
  return { color, Icon: severity === 'critical' ? WarningAmberOutlined : AccessTimeOutlined };
};

// Null when the integration has no health yet (unknown)
export const readHealthStatus = (key?: IngestionHealthSummary_ingestionHealth$key | null): string | null => {
  return key ? readInlineData(ingestionHealthSummaryFragment, key).status : null;
};

// Null when the integration has no health yet (unknown) or is healthy: nothing to flag
export const readHealthIssue = (key?: IngestionHealthSummary_ingestionHealth$key | null): HealthIssue | null => {
  if (!key) return null;
  const { status, healthChecks } = readInlineData(ingestionHealthSummaryFragment, key);
  if (status !== 'critical' && status !== 'degraded') return null;
  const check = healthChecks[0];
  return { severity: status, message: check?.health_check_message ?? check?.health_check_code ?? null };
};
