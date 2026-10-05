import React from 'react';
import { Box } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { ErrorOutlineOutlined, ShieldOutlined } from '@mui/icons-material';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import type { Theme } from '../../../../../components/Theme';
import { hexToRGB } from '../../../../../utils/Colors';
import { useFormatter } from '../../../../../components/i18n';
import {
  computeLayerLevel,
  DEFENSE_COVERED_LEVEL,
  DEFENSE_LEVEL_NONE,
  type DefenseCellLike,
  defenseFailedColor,
  type DefenseLayersState,
  defenseLevelColor,
  defenseLevelLabel,
  defenseLevelTextColor,
  defenseThreatColor,
  isValidationFailed,
} from '../../../defense/matrix/defenseMatrix-utils';

export interface DefenseMatrixCellData extends DefenseCellLike {
  readonly attack_pattern_id: string;
  readonly mitigated: boolean;
  readonly threats_count: number;
}

export interface DefenseMatrixMode {
  cells: ReadonlyMap<string, DefenseMatrixCellData>;
  layers: DefenseLayersState;
  // Techniques used by the threats of the overlay are outlined
  threatOverlay: boolean;
  // Levels the matrix is restricted to (status header counters), null for every level
  levelFilter?: ReadonlyArray<number> | null;
  selectedId?: string | null;
  onSelect: (attackPatternId: string) => void;
}

export const defenseCellLevel = (defense: DefenseMatrixMode, attackPatternId: string) => {
  const cell = defense.cells.get(attackPatternId);
  return cell ? computeLayerLevel(cell, defense.layers) : DEFENSE_LEVEL_NONE;
};

// The counters count the stored levels, whatever layers are shown: their filter matches the same levels
export const isInDefenseLevelFilter = (defense: DefenseMatrixMode, attackPatternId: string) => {
  if (!defense.levelFilter) return true;
  return defense.levelFilter.includes(defense.cells.get(attackPatternId)?.level ?? DEFENSE_LEVEL_NONE);
};

// A displayed technique matches a counter at the best stored level of itself and its sub-techniques, as counted
export const isTechniqueInDefenseLevelFilter = (defense: DefenseMatrixMode, attackPatternIds: ReadonlyArray<string>) => {
  if (!defense.levelFilter) return true;
  const level = Math.max(DEFENSE_LEVEL_NONE, ...attackPatternIds.map((id) => defense.cells.get(id)?.level ?? DEFENSE_LEVEL_NONE));
  return defense.levelFilter.includes(level);
};

// A technique counts once, at the best level of itself and its sub-techniques, as in the coverage by tactic
export const defenseTechniqueLevel = (defense: DefenseMatrixMode, attackPatternIds: ReadonlyArray<string>) => {
  return Math.max(DEFENSE_LEVEL_NONE, ...attackPatternIds.map((id) => defenseCellLevel(defense, id)));
};

// Each entry holds the ids of a displayed technique and of its sub-techniques
export const defenseCoveredPercent = (defense: DefenseMatrixMode, techniques: ReadonlyArray<ReadonlyArray<string>>) => {
  if (techniques.length === 0) return 0;
  const covered = techniques.filter((ids) => defenseTechniqueLevel(defense, ids) >= DEFENSE_COVERED_LEVEL).length;
  return Math.round((covered / techniques.length) * 100);
};

export const isUsedByThreats = (defense: DefenseMatrixMode, attackPatternId: string) => {
  return defense.threatOverlay && (defense.cells.get(attackPatternId)?.threats_count ?? 0) > 0;
};

export const getDefenseBoxStyles = ({
  defense,
  attackPatternId,
  level,
  isHovered,
  theme,
}: {
  defense: DefenseMatrixMode;
  attackPatternId: string;
  level: number;
  isHovered: boolean;
  theme: Theme;
}) => {
  const color = defenseLevelColor(theme, level);
  const usedByThreats = isUsedByThreats(defense, attackPatternId);
  const isSelected = defense.selectedId === attackPatternId;
  let backgroundColor = isHovered ? hexToRGB(theme.palette.common.white, 0.1) : 'transparent';
  if (level > DEFENSE_LEVEL_NONE) {
    backgroundColor = hexToRGB(color, isHovered ? 0.35 : 0.22);
  }
  let outline = 'none';
  if (isSelected) {
    outline = `2px solid ${theme.palette.primary.main}`;
  } else if (usedByThreats) {
    outline = `2px solid ${defenseThreatColor(theme)}`;
  }
  return {
    border: `1px solid ${level > DEFENSE_LEVEL_NONE ? color : theme.palette.background.accent}`,
    backgroundColor,
    outline,
    outlineOffset: '-2px',
  };
};

export const useDefenseCellLabel = () => {
  const { t_i18n } = useFormatter();
  return (defense: DefenseMatrixMode, attackPatternId: string, name: string) => {
    const cell = defense.cells.get(attackPatternId);
    const level = defenseCellLevel(defense, attackPatternId);
    const parts = [name, defenseLevelLabel(t_i18n, level)];
    if (cell && isUsedByThreats(defense, attackPatternId)) {
      parts.push(t_i18n('{count, plural, one {Used by # threat} other {Used by # threats}}', { values: { count: cell.threats_count } }));
    }
    return parts.join(' - ');
  };
};

/**
 * Accessible keyboard activation for the clickable matrix boxes of the defense mode.
 */
export const defenseKeyboardProps = (defense: DefenseMatrixMode, attackPatternId: string) => ({
  role: 'button',
  tabIndex: 0,
  onKeyDown: (event: React.KeyboardEvent) => {
    // Keys pressed on a nested control (the expand button of an accordion summary) belong to that control
    if (event.target !== event.currentTarget) return;
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      event.stopPropagation();
      defense.onSelect(attackPatternId);
    }
  },
});

const MarkerTooltip = ({ title, children }: { title: string; children: React.ReactElement }) => (
  <Tooltip>
    <TooltipTrigger asChild>{children}</TooltipTrigger>
    <TooltipContent>{title}</TooltipContent>
  </Tooltip>
);

const badgeSx = {
  fontSize: 9,
  fontWeight: 600,
  lineHeight: '14px',
  minWidth: 14,
  paddingInline: 0.5,
  borderRadius: '7px',
  textAlign: 'center',
} as const;

const AttackPatternsMatrixDefenseMarkers = ({ defense, attackPatternId }: { defense: DefenseMatrixMode; attackPatternId: string }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const cell = defense.cells.get(attackPatternId);
  if (!cell) return null;
  const level = defenseCellLevel(defense, attackPatternId);
  const failed = isValidationFailed(cell, defense.layers);
  const mitigated = defense.layers.mitigations && cell.mitigated;
  const usedByThreats = isUsedByThreats(defense, attackPatternId);
  if (level === DEFENSE_LEVEL_NONE && !failed && !mitigated && !usedByThreats) return null;
  const levelColor = defenseLevelColor(theme, level);
  const threatColor = defenseThreatColor(theme);
  return (
    <Box sx={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 0.25, flexShrink: 0 }}>
      {failed && (
        <MarkerTooltip title={t_i18n('The latest OpenAEV validation failed')}>
          <ErrorOutlineOutlined aria-label={t_i18n('Validation failed')} sx={{ fontSize: 14, color: defenseFailedColor(theme) }} />
        </MarkerTooltip>
      )}
      {mitigated && (
        <MarkerTooltip title={t_i18n('Mitigated by a course of action')}>
          <ShieldOutlined aria-label={t_i18n('Mitigated')} sx={{ fontSize: 14 }} />
        </MarkerTooltip>
      )}
      {usedByThreats && (
        <MarkerTooltip title={t_i18n('{count, plural, one {Used by # threat} other {Used by # threats}}', { values: { count: cell.threats_count } })}>
          <Box component="span" sx={{ ...badgeSx, color: defenseLevelTextColor(theme, threatColor), backgroundColor: threatColor }}>
            {cell.threats_count}
          </Box>
        </MarkerTooltip>
      )}
      {level > DEFENSE_LEVEL_NONE && (
        // The level is also written, so that it never depends on the colour alone
        <MarkerTooltip title={defenseLevelLabel(t_i18n, level)}>
          <Box component="span" data-testid={`defense-cell-level-${attackPatternId}`} sx={{ ...badgeSx, color: defenseLevelTextColor(theme, levelColor), backgroundColor: levelColor }}>
            {level}
          </Box>
        </MarkerTooltip>
      )}
    </Box>
  );
};

export default AttackPatternsMatrixDefenseMarkers;
