import React from 'react';
import { Box } from '@mui/material';
import { ErrorOutlineOutlined, ShieldOutlined } from '@mui/icons-material';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import type { Theme } from '../../../../../components/Theme';
import { hexToRGB } from '../../../../../utils/Colors';
import { useFormatter } from '../../../../../components/i18n';
import {
  computeLayerLevel,
  DEFENSE_FAILED_COLOR,
  DEFENSE_LEVEL_LABELS,
  DEFENSE_LEVEL_NONE,
  DEFENSE_THREAT_COLOR,
  type DefenseCellLike,
  type DefenseLayersState,
  defenseLevelColor,
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
  selectedId?: string | null;
  onSelect: (attackPatternId: string) => void;
}

export const defenseCellLevel = (defense: DefenseMatrixMode, attackPatternId: string) => {
  const cell = defense.cells.get(attackPatternId);
  return cell ? computeLayerLevel(cell, defense.layers) : DEFENSE_LEVEL_NONE;
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
  const color = defenseLevelColor(level);
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
    outline = `2px solid ${DEFENSE_THREAT_COLOR}`;
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
    const parts = [name, `${t_i18n('Defense level')} ${level}`, t_i18n(DEFENSE_LEVEL_LABELS[level])];
    if (cell && isUsedByThreats(defense, attackPatternId)) {
      parts.push(t_i18n('Used by {count} threats', { values: { count: cell.threats_count } }));
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

const AttackPatternsMatrixDefenseMarkers = ({ defense, attackPatternId }: { defense: DefenseMatrixMode; attackPatternId: string }) => {
  const { t_i18n } = useFormatter();
  const cell = defense.cells.get(attackPatternId);
  if (!cell) return null;
  const failed = isValidationFailed(cell, defense.layers);
  const mitigated = defense.layers.mitigations && cell.mitigated;
  const usedByThreats = isUsedByThreats(defense, attackPatternId);
  if (!failed && !mitigated && !usedByThreats) return null;
  return (
    <Box sx={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 0.25, flexShrink: 0 }}>
      {failed && (
        <MarkerTooltip title={t_i18n('The latest OpenAEV validation failed')}>
          <ErrorOutlineOutlined aria-label={t_i18n('Validation failed')} sx={{ fontSize: 14, color: DEFENSE_FAILED_COLOR }} />
        </MarkerTooltip>
      )}
      {mitigated && (
        <MarkerTooltip title={t_i18n('Mitigated by a course of action')}>
          <ShieldOutlined aria-label={t_i18n('Mitigated')} sx={{ fontSize: 14 }} />
        </MarkerTooltip>
      )}
      {usedByThreats && (
        <MarkerTooltip title={t_i18n('Used by {count} threats', { values: { count: cell.threats_count } })}>
          <Box
            component="span"
            sx={{
              fontSize: 9,
              fontWeight: 600,
              lineHeight: '14px',
              minWidth: 14,
              paddingInline: 0.5,
              borderRadius: '7px',
              textAlign: 'center',
              color: '#ffffff',
              backgroundColor: DEFENSE_THREAT_COLOR,
            }}
          >
            {cell.threats_count}
          </Box>
        </MarkerTooltip>
      )}
    </Box>
  );
};

export default AttackPatternsMatrixDefenseMarkers;
