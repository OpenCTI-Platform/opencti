import { graphql, readInlineData } from 'react-relay';
import { AccessTimeOutlined, WarningAmberOutlined } from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';
import { useIngestionHealthColor, type HealthIssueSeverity } from '@components/data/connectors/ingestionHealthDisplay';
import { type HealthCheckMessageSource } from '@components/data/connectors/useHealthCheckMessage';
import type { IngestionHealthSummary_ingestionHealth$key } from './__generated__/IngestionHealthSummary_ingestionHealth.graphql';

// Read as plain data, outside of any component: the integrations page aggregates the health of every item.
// Spread next to IngestionHealthChip_ingestionHealth in the queries feeding the deployed integrations.
const ingestionHealthSummaryFragment = graphql`
  fragment IngestionHealthSummary_ingestionHealth on IngestionHealth @inline {
    status
    healthChecks {
      health_check_code
      health_check_message
      health_check_metadata
      health_check_kind
      health_check_severity
    }
  }
`;

export interface HealthIssue {
  severity: HealthIssueSeverity;
  // First failing check of the severity of the status, worded by getHealthCheckMessage; null when the status carries none
  check: HealthCheckMessageSource | null;
  // Failing checks of the same severity that are not shown: displayed as (+x) next to the check
  othersCount: number;
}

// The count of the other checks of the same severity, as displayed next to the message of the check: empty when there is none
export const formatOthersCount = (othersCount: number): string => (othersCount > 0 ? `(+${othersCount})` : '');

// Color and icon every marker of a health issue shares: critical = red / warning, degraded = orange / clock
export const useHealthIssueDisplay = (severity: HealthIssue['severity']): { color: string; Icon: SvgIconComponent } => {
  const healthColor = useIngestionHealthColor();
  // Same colors as every other health marker; the theme colors are optional in its type
  const color = healthColor(severity) ?? 'inherit';
  return { color, Icon: severity === 'critical' ? WarningAmberOutlined : AccessTimeOutlined };
};

// Null when the integration has no health: not evaluated yet, or stopped. Unknown is a status like any other once evaluated
export const readHealthStatus = (key?: IngestionHealthSummary_ingestionHealth$key | null): string | null => {
  return key ? readInlineData(ingestionHealthSummaryFragment, key).status : null;
};

// Null when the integration has no health (not evaluated yet, or stopped) or is neither critical nor degraded: nothing to flag
export const readHealthIssue = (key?: IngestionHealthSummary_ingestionHealth$key | null): HealthIssue | null => {
  if (!key) return null;
  const { status, healthChecks } = readInlineData(ingestionHealthSummaryFragment, key);
  if (status !== 'critical' && status !== 'degraded') return null;
  // Same rule as the backend status: only a blocking runtime check is critical. The checks of the other severity are not this issue
  const sameSeverityChecks = healthChecks.filter((check) => {
    const isCritical = check.health_check_kind === 'runtime' && check.health_check_severity === 'blocking';
    return isCritical === (status === 'critical');
  });
  return { severity: status, check: sameSeverityChecks[0] ?? null, othersCount: Math.max(sameSeverityChecks.length - 1, 0) };
};
