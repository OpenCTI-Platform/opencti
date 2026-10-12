import React from 'react';
import Box from '@mui/material/Box';
import { alpha, useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';
import Label from '@common/label/Label';
import { useFormatter } from '../../../../components/i18n';
interface ThreatPulseUniquenessMeterProps {
  score: number;
  // One short line saying what the score means for the analyst.
  meaning?: string;
}

/**
 * The community uniqueness of an object on its 0-100 scale: 0 when the whole community holds it, 100 when fewer
 * platforms than the anonymity threshold do. A tick marks the score, so that 0 still reads as a position on the scale.
 * FDS-WORKAROUND #67: the library ProgressBar is a progressbar by contract and has no meter - see
 * fds-migration/LIBRARY-FEEDBACK.md #67.
 */
const ThreatPulseUniquenessMeter = ({ score, meaning }: ThreatPulseUniquenessMeterProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const value = Math.min(100, Math.max(0, score));
  const valueText = t_i18n('{score} out of 100', { values: { score: value } });
  return (
    <Box data-testid="threat-pulse-uniqueness" sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        <Label sx={{ marginBottom: 0, flexShrink: 0 }}>{t_i18n('Community uniqueness')}</Label>
        <Box
          role="meter"
          aria-label={t_i18n('Community uniqueness')}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={value}
          aria-valuetext={valueText}
          sx={{ position: 'relative', flex: 1, minWidth: 64, height: 6, borderRadius: 1, backgroundColor: alpha(theme.palette.text.primary, 0.08) }}
        >
          <Box sx={{ position: 'absolute', insetBlock: 0, left: 0, width: `${value}%`, borderRadius: 1, backgroundColor: alpha(theme.palette.primary.main, 0.6) }} />
          <Box
            sx={{
              position: 'absolute',
              top: -4,
              left: `clamp(0px, calc(${value}% - 1.5px), calc(100% - 3px))`,
              width: 3,
              height: 14,
              borderRadius: 0.5,
              backgroundColor: theme.palette.primary.main,
            }}
          />
        </Box>
        <Text as="span" variant="content-compact-bold" style={{ flexShrink: 0 }}>{valueText}</Text>
      </Box>
      {meaning && (
        <Text variant="content-compact" style={{ color: theme.palette.text.secondary }} data-testid="threat-pulse-uniqueness-meaning">
          {meaning}
        </Text>
      )}
    </Box>
  );
};

export default ThreatPulseUniquenessMeter;
