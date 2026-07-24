import React from 'react';
import { Box, Checkbox, Tooltip, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import MatrixEntityMarker from '../../techniques/attack_patterns/attack_patterns_matrix/MatrixEntityMarker';
import { MatrixEntityUsage } from './investigationMatrixUsage';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

interface InvestigationMatrixLegendProps {
  legend: MatrixEntityUsage[];
  // Whether has-covered coverage donuts are shown on the matrix, to explain the
  // separate red -> green coverage scale in the legend.
  hasCoverage?: boolean;
  // Ids of entities whose markers are currently toggled off (hidden on the matrix).
  hiddenEntityIds?: Set<string>;
  // Toggle a single entity's marker visibility on the matrix.
  onToggleEntity?: (entityId: string) => void;
  // When the frequency heatmap is active, the relative min/max used to render
  // the yellow -> red "Risk" scale.
  heatmapScale?: { min: number; max: number };
}

// Bottom legend bar mapping each colour + shape marker to the entity it represents.
// Each entity has a selection box to control whether its markers show on the matrix.
const InvestigationMatrixLegend = ({
  legend,
  hasCoverage = false,
  hiddenEntityIds,
  onToggleEntity,
  heatmapScale,
}: InvestigationMatrixLegendProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  if (legend.length === 0 && !hasCoverage && !heatmapScale) {
    return null;
  }

  return (
    <Box
      sx={{
        flex: '0 0 auto',
        borderTop: `1px solid ${theme.palette.divider}`,
        backgroundColor: theme.palette.background.paper,
        paddingBlock: 1,
        paddingInline: 2,
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        gap: 2,
        maxHeight: 96,
        overflowY: 'auto',
      }}
    >
      {legend.length > 0 && (
        <Typography variant="caption" sx={{ fontWeight: 600, marginRight: 1 }}>
          {t_i18n('Entities using techniques')}
        </Typography>
      )}
      {legend.map((entity) => {
        const isHidden = hiddenEntityIds?.has(entity.id) ?? false;
        const isToggleable = typeof onToggleEntity === 'function';
        return (
          <Tooltip
            key={entity.id}
            title={isToggleable
              ? (isHidden ? t_i18n('Show on matrix') : t_i18n('Hide from matrix'))
              : ''}
          >
            <Box
              onClick={isToggleable ? () => onToggleEntity(entity.id) : undefined}
              sx={{
                display: 'flex',
                alignItems: 'center',
                gap: 0.25,
                cursor: isToggleable ? 'pointer' : 'default',
                userSelect: 'none',
              }}
            >
              {isToggleable && (
                <Checkbox
                  size="small"
                  checked={!isHidden}
                  disableRipple
                  sx={{ padding: 0.25 }}
                  inputProps={{ 'aria-label': entity.name }}
                />
              )}
              <MatrixEntityMarker shape={entity.shape} color={entity.color} label={entity.name} />
              <Typography
                variant="caption"
                noWrap
                sx={{ opacity: isHidden ? 0.5 : 1 }}
              >
                {entity.name}
              </Typography>
            </Box>
          </Tooltip>
        );
      })}
      {hasCoverage && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, marginLeft: legend.length > 0 ? 2 : 0 }}>
          <Box
            sx={{
              width: 40,
              height: 10,
              borderRadius: 5,
              background: `linear-gradient(to right, ${theme.palette.error.main}, ${theme.palette.success.main})`,
            }}
          />
          <Typography variant="caption" noWrap>
            {t_i18n('Coverage score (low \u2192 high, detection & prevention)')}
          </Typography>
        </Box>
      )}
      {heatmapScale && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, marginLeft: (legend.length > 0 || hasCoverage) ? 2 : 0 }}>
          <Typography variant="caption" sx={{ fontWeight: 600 }}>
            {t_i18n('Risk')}
          </Typography>
          <Typography variant="caption">{heatmapScale.min}</Typography>
          <Box
            sx={{
              width: 60,
              height: 10,
              borderRadius: 5,
              background: 'linear-gradient(to right, rgb(253, 246, 179), rgb(252, 205, 144), rgb(245, 150, 137))',
            }}
          />
          <Typography variant="caption">{heatmapScale.max}</Typography>
          <Typography variant="caption" noWrap sx={{ marginLeft: 0.5 }}>
            {t_i18n('Technique usage (low \u2192 high)')}
          </Typography>
        </Box>
      )}
    </Box>
  );
};

export default InvestigationMatrixLegend;
