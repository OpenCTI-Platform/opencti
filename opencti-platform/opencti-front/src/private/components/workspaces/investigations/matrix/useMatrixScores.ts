import { useMemo } from 'react';
import { useFormatter } from '../../../../../components/i18n';
import { scoreLinks, type ScoringLink } from './ttpAnalyser';
import { computeHeatScale } from './heatScale';
import { buildCellDecorations, type MatrixTechniqueNode } from './buildCellDecorations';
import type { InvestigationAttackPattern } from './investigationMatrixUtils';
import { filterScoringLinks, hasActiveMatrixFilters, type InvestigationMatrixFilters } from './matrixFilters';

interface MatrixScoresInput {
  /** Every scoring link of the investigation; the filters are applied here. */
  links: ScoringLink[];
  filters: InvestigationMatrixFilters;
  attackPatterns: InvestigationAttackPattern[];
  /** The techniques of the kill chain shown: the heat scale comes from them only. */
  techniqueIds: Set<string>;
  techniques: MatrixTechniqueNode[];
  heatmapSelected: boolean;
}

/**
 * The scores of the matrix: links kept by the filters, scored, put on the heat scale of the kill chain shown,
 * and turned into cell decorations. Also tells the toolbar whether the heatmap can be turned on.
 */
const useMatrixScores = ({ links, filters, attackPatterns, techniqueIds, techniques, heatmapSelected }: MatrixScoresInput) => {
  const { t_i18n } = useFormatter();
  const isEmpty = attackPatterns.length === 0;

  const keptLinks = useMemo(() => filterScoringLinks(links, filters), [links, filters]);
  const usage = useMemo(() => scoreLinks(keptLinks), [keptLinks]);
  const heatScale = useMemo(() => computeHeatScale(usage, techniqueIds), [usage, techniqueIds]);
  const hasScores = !isEmpty && heatScale.max > 0;

  // The filters are blamed only when clearing them would bring scores back in this kill chain: not when only
  // stale ids are stored, nor when the kill chain itself has no score.
  const hasUnfilteredScores = useMemo(() => {
    if (isEmpty || hasScores || !hasActiveMatrixFilters(filters)) return false;
    return computeHeatScale(scoreLinks(links), techniqueIds).max > 0;
  }, [isEmpty, hasScores, filters, links, techniqueIds]);
  const heatmapDisabledReason = hasUnfilteredScores
    ? t_i18n('No attack pattern is left linked to an entity with these filters')
    : undefined;

  // A kill chain without scores turns the heatmap off without forgetting the user's choice.
  const heatmapOn = heatmapSelected && hasScores;
  const investigationIds = useMemo(() => new Set(attackPatterns.map(({ id }) => id)), [attackPatterns]);
  // Without any score, cells render exactly as in US.1: no decoration at all.
  const cellDecorations = useMemo(
    () => (hasScores
      ? buildCellDecorations({ usage, scale: heatScale, techniques, investigationIds, heatmapOn, t: t_i18n })
      : undefined),
    [hasScores, usage, heatScale, techniques, investigationIds, heatmapOn, t_i18n],
  );

  return { hasScores, heatmapOn, heatMax: heatScale.max, heatmapDisabledReason, cellDecorations };
};

export default useMatrixScores;
