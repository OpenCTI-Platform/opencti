import React from 'react';
import { useTheme } from '@mui/material/styles';
import Tag from '@common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import {
  buildHealthTooltipLines,
  HEALTH_PALETTE_TOKEN,
  HEALTH_STATUS_LABEL,
  type IngestionHealth,
} from '../../../../utils/IngestionHealth';

interface IngestionHealthChipProps {
  health?: IngestionHealth | null;
}

// One chip for all seven ingestion source kinds. Colour comes from palette
// tokens only — `palette.error`, `palette.warn` and `palette.success` are
// migrated zones, so a hex literal here would fail check-fds-conformity.
const IngestionHealthChip: React.FC<IngestionHealthChipProps> = ({ health }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  // No health resolved yet (source never evaluated, or the field errored):
  // say so rather than implying the source is fine.
  const status = health?.status ?? 'unknown';
  const token = HEALTH_PALETTE_TOKEN[status];

  const colorByToken: Record<string, string | undefined> = {
    error: theme.palette.error.main,
    warn: theme.palette.warn.main,
    success: theme.palette.success.main,
    neutral: undefined,
  };

  const tooltipLines = buildHealthTooltipLines(health);
  const tooltipTitle = tooltipLines.length > 0
    ? (
      <div>
        {tooltipLines.map((line) => (
          <div key={line}>{line}</div>
        ))}
      </div>
      )
    : undefined;

  return (
    <Tag
      label={t_i18n(HEALTH_STATUS_LABEL[status])}
      color={colorByToken[token]}
      tooltipTitle={tooltipTitle}
    />
  );
};

export default IngestionHealthChip;
