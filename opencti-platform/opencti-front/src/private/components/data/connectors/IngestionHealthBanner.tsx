import React from 'react';
import { useTheme } from '@mui/material/styles';
import { Icon, Paper, Text } from '@filigran/design-system';

interface IngestionHealthBannerProps {
  severity: 'critical' | 'degraded';
  title: string;
  // Details under the title, one per line
  lines?: string[];
  // Trailing control, a secondary small Button
  action?: React.ReactNode;
  'data-testid'?: string;
}

// Same look as the design system Alert (severity bar, glyph, title, details, action), built on Paper and Text:
// the Alert renders its texts as <p> keeping the browser margins, which makes a health banner too tall
const SEVERITY_STYLE = {
  critical: { role: 'alert', bar: 'border-alert-error', icon: 'circle-x', iconColor: 'text-icon-error' },
  degraded: { role: 'alert', bar: 'border-alert-warning', icon: 'triangle-alert', iconColor: 'text-icon-warning' },
} as const;

const IngestionHealthBanner = ({ severity, title, lines = [], action, 'data-testid': testId }: IngestionHealthBannerProps) => {
  const theme = useTheme();
  const { role, bar, icon, iconColor } = SEVERITY_STYLE[severity];
  return (
    <Paper
      elevation={2}
      padding={8}
      role={role}
      data-testid={testId}
      // border-0 drops the Paper border, border-l-4 (later in the library CSS) brings back the left bar only
      className={`flex items-center border-0 border-l-4 ${bar}`}
      style={{ gap: theme.spacing(2) }}
    >
      <div className="flex min-w-0 flex-1 items-center" style={{ gap: theme.spacing(2), paddingLeft: theme.spacing(1) }}>
        <span className="flex shrink-0 items-center" style={{ width: theme.spacing(2), height: theme.spacing(3) }}>
          <Icon name={icon} size={16} className={iconColor} />
        </span>
        <div className="flex min-w-0 flex-1 flex-col items-start">
          <Text variant="title-xs" className="w-full break-words text-alert">{title}</Text>
          {lines.map((line, index) => (
            <Text key={`${index}-${line}`} variant="content-compact" className="w-full break-words text-default-secondary">{line}</Text>
          ))}
        </div>
      </div>
      {action && <div className="flex shrink-0 items-center" style={{ gap: theme.spacing(1) }}>{action}</div>}
    </Paper>
  );
};

export default IngestionHealthBanner;
