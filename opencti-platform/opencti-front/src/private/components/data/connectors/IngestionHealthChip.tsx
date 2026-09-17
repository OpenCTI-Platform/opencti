import React from 'react';
import { useTheme } from '@mui/material/styles';
import Tag from '@common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
import useIngestionHealthEnabled from '../../../../utils/hooks/useIngestionHealthEnabled';
import type { Theme } from '../../../../components/Theme';
import {
  buildConfigurationLines,
  buildHealthTooltipLines,
  hasConfigurationFinding,
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
  const healthEnabled = useIngestionHealthEnabled();

  // Rendered nothing at all when the feature is off — not an "Unknown" chip.
  // The field soft-fails to null in that case, so without this every row would
  // show a grey chip claiming the platform cannot tell.
  if (!healthEnabled) {
    return null;
  }

  // null and `unknown` are different answers, and the difference matters.
  // `unknown` means evaluated but never observed running. null means not
  // evaluated at all — a built-in connector that is platform plumbing rather
  // than an ingestion source, or a resolver that failed. Neither deserves a
  // chip, and showing "Unknown" for them reads as a fault that is not there.
  if (!health) {
    return null;
  }
  const status = health.status;
  const token = HEALTH_PALETTE_TOKEN[status];

  const colorByToken: Record<string, string | undefined> = {
    error: theme.palette.error.main,
    warn: theme.palette.warn.main,
    success: theme.palette.success.main,
    neutral: undefined,
  };

  // The runtime tooltip carries runtime checks; configuration findings get
  // their own marker so neither axis hides the other.
  const tooltipLines = buildHealthTooltipLines(health).filter(
    (line) => !buildConfigurationLines(health).includes(line),
  );
  const misconfigured = hasConfigurationFinding(health);
  const tooltipTitle = tooltipLines.length > 0
    ? (
      <div>
        {tooltipLines.map((line) => (
          <div key={line}>{line}</div>
        ))}
      </div>
      )
    : undefined;

  const configurationLines = buildConfigurationLines(health);

  return (
    <>
      <Tag
        label={t_i18n(HEALTH_STATUS_LABEL[status])}
        color={colorByToken[token]}
        tooltipTitle={tooltipTitle}
      />
      {misconfigured && (
        <Tag
          label={t_i18n('Misconfigured')}
          color={theme.palette.warn.main}
          tooltipTitle={(
            <div>
              {configurationLines.map((line) => (
                <div key={line}>{line}</div>
              ))}
            </div>
          )}
        />
      )}
    </>
  );
};

export default IngestionHealthChip;
