import React from 'react';
import { Box, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { DEFENSE_LEVEL_DESCRIPTIONS, DEFENSE_LEVEL_LABELS, DEFENSE_LEVELS, defenseLevelColor, defenseLevelLabel, summarizeLevels } from './defenseMatrix-utils';

interface DefenseLevelsBarProps {
  // Number of techniques per level, index = level
  levels: ReadonlyArray<number>;
  height?: number;
  label?: string;
}

/**
 * Stacked distribution of techniques per defense level, each segment explained on hover.
 */
export const DefenseLevelsBar = ({ levels, height = 12, label }: DefenseLevelsBarProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { total } = summarizeLevels(levels);
  const segmentLabel = (level: number) => {
    const count = levels[level] ?? 0;
    return t_i18n('{label}: {count, plural, one {# technique} other {# techniques}} ({share}%)', {
      values: { label: t_i18n(DEFENSE_LEVEL_LABELS[level]), count, share: total === 0 ? 0 : Math.round((count / total) * 100) },
    });
  };
  // The segments cannot take the focus: a custom summary leads the counts of every level, it never replaces them
  const levelsSummary = DEFENSE_LEVELS.map(segmentLabel).join(', ');
  return (
    <Box
      role="img"
      aria-label={label ? `${label}. ${levelsSummary}` : levelsSummary}
      sx={{ display: 'flex', width: '100%', height, borderRadius: '4px', overflow: 'hidden', backgroundColor: 'action.hover' }}
    >
      {total > 0 && DEFENSE_LEVELS.map((level) => {
        const count = levels[level] ?? 0;
        if (count === 0) return null;
        return (
          <Tooltip key={level}>
            <TooltipTrigger asChild>
              <Box sx={{ width: `${(count / total) * 100}%`, backgroundColor: defenseLevelColor(theme, level) }} />
            </TooltipTrigger>
            <TooltipContent>{segmentLabel(level)}</TooltipContent>
          </Tooltip>
        );
      })}
    </Box>
  );
};

/**
 * Legend of the five defense levels with their meaning.
 */
export const DefenseLevelsLegend = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <Box component="ul" aria-label={t_i18n('Defense levels')} sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, margin: 0, padding: 0, listStyle: 'none' }}>
      {DEFENSE_LEVELS.map((level) => (
        <Tooltip key={level}>
          <TooltipTrigger asChild>
            <Box component="li" tabIndex={0} sx={{ display: 'flex', alignItems: 'center', gap: 0.75, cursor: 'help' }}>
              <Box sx={{ width: 12, height: 12, borderRadius: '2px', backgroundColor: defenseLevelColor(theme, level) }} />
              <Typography variant="caption">{defenseLevelLabel(t_i18n, level)}</Typography>
            </Box>
          </TooltipTrigger>
          <TooltipContent>{t_i18n(DEFENSE_LEVEL_DESCRIPTIONS[level])}</TooltipContent>
        </Tooltip>
      ))}
    </Box>
  );
};
