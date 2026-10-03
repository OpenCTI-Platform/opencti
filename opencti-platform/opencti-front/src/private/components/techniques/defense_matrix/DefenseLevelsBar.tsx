import React from 'react';
import { Box, Typography } from '@mui/material';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { DEFENSE_LEVEL_DESCRIPTIONS, DEFENSE_LEVEL_LABELS, DEFENSE_LEVELS, defenseLevelColor, summarizeLevels } from './defenseMatrix-utils';

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
  const { total } = summarizeLevels(levels);
  return (
    <Box
      role="img"
      aria-label={label ?? DEFENSE_LEVELS.map((level) => `${t_i18n(DEFENSE_LEVEL_LABELS[level])}: ${levels[level] ?? 0}`).join(', ')}
      sx={{ display: 'flex', width: '100%', height, borderRadius: '4px', overflow: 'hidden', backgroundColor: 'action.hover' }}
    >
      {total > 0 && DEFENSE_LEVELS.map((level) => {
        const count = levels[level] ?? 0;
        if (count === 0) return null;
        return (
          <Tooltip key={level}>
            <TooltipTrigger asChild>
              <Box sx={{ width: `${(count / total) * 100}%`, backgroundColor: defenseLevelColor(level), opacity: level === 0 ? 0.45 : 1 }} />
            </TooltipTrigger>
            <TooltipContent>{`${t_i18n(DEFENSE_LEVEL_LABELS[level])}: ${count} (${Math.round((count / total) * 100)}%)`}</TooltipContent>
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
  return (
    <Box component="ul" aria-label={t_i18n('Defense levels')} sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, margin: 0, padding: 0, listStyle: 'none' }}>
      {DEFENSE_LEVELS.map((level) => (
        <Tooltip key={level}>
          <TooltipTrigger asChild>
            <Box component="li" tabIndex={0} sx={{ display: 'flex', alignItems: 'center', gap: 0.75, cursor: 'help' }}>
              <Box sx={{ width: 12, height: 12, borderRadius: '2px', backgroundColor: defenseLevelColor(level), opacity: level === 0 ? 0.45 : 1 }} />
              <Typography variant="caption">{`${level} - ${t_i18n(DEFENSE_LEVEL_LABELS[level])}`}</Typography>
            </Box>
          </TooltipTrigger>
          <TooltipContent>{t_i18n(DEFENSE_LEVEL_DESCRIPTIONS[level])}</TooltipContent>
        </Tooltip>
      ))}
    </Box>
  );
};
