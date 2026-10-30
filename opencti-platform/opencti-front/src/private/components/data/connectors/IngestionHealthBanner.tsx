import React from 'react';
import { Box } from '@mui/material';
import { Alert } from '@filigran/design-system';
import type { HealthIssueSeverity } from '@components/data/connectors/ingestionHealthDisplay';

interface IngestionHealthBannerProps {
  severity: HealthIssueSeverity;
  title: string;
  // Details under the title, one per line
  lines?: string[];
  // Trailing control, a secondary small Button
  action?: React.ReactNode;
  'data-testid'?: string;
}

const ALERT_SEVERITY = { critical: 'error', degraded: 'warning' } as const;

// The design system Alert. FDS-WORKAROUND #71: it renders title and description as <p> and the library ships no
// preflight, so they keep the browser margins and the banner gets too tall. See fds-migration/LIBRARY-FEEDBACK.md #71
const IngestionHealthBanner = ({ severity, title, lines = [], action, 'data-testid': testId }: IngestionHealthBannerProps) => (
  <Box
    sx={{
      '& p': { margin: 0 },
      // No bold: title and details share the regular weight
      '& [role] p, & [role] p span': { fontWeight: 'normal' },
      '& [role]': { padding: 2 },
      '& [role] > div:first-of-type': { alignItems: 'center' },
    }}
  >
    <Alert
      data-testid={testId}
      severity={ALERT_SEVERITY[severity]}
      title={title}
      // The description is a <p>, hence spans
      description={lines.length > 0 && lines.map((line, index) => (
        <span key={`${index}-${line}`} style={{ display: 'block' }}>{line}</span>
      ))}
      action={action}
    />
  </Box>
);

export default IngestionHealthBanner;
