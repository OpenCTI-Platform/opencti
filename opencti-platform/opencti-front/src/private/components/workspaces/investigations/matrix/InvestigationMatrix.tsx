import React, { Suspense, useMemo } from 'react';
import { PreloadedQuery } from 'react-relay';
import { Text } from '@filigran/design-system';
import AttackPatternsMatrix, { attackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import { attackPatternsMatrixColumnsFragment } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import { AttackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import { AttackPatternsMatrixColumns_data$key } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixColumns_data.graphql';
import { ErrorBoundary } from '@components/Error';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import type { GraphState } from '../../../../../components/graph/graph.types';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import { GRAPH_TOOLBAR_HEIGHT, GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE } from '../../../../../components/graph/utils/graphFraming';
import Loader from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import usePreloadedFragment from '../../../../../utils/hooks/usePreloadedFragment';
import { INVESTIGATION_MATRIX_EXPORT_ID } from '../InvestigationViewSwitcher';
import { getScoringLinks } from './ttpAnalyser';
import HeatmapLegend from './HeatmapLegend';
import InvestigationMatrixToolbar from './InvestigationMatrixToolbar';
import { EXPORT_ONLY_ATTRIBUTE } from './prepareMatrixCapture';
import { getInvestigationAttackPatterns, getUnplacedAttackPatterns, MatrixPhase } from './investigationMatrixUtils';
import type { InvestigationMatrixSettings, InvestigationMatrixSettingsChange } from './investigationMatrixSettings';
import type { InvestigationMatrixFilters } from './matrixFilters';
import useMatrixKillChain from './useMatrixKillChain';
import useSecurityPosture from './useSecurityPosture';
import useMatrixScores from './useMatrixScores';
import useMatrixFilterControls from './useMatrixFilterControls';

const NO_PHASES: ReadonlyArray<MatrixPhase> = [];
// The time range panel grows the toolbar over the bottom of the view.
const TIME_RANGE_PANEL_HEIGHT = GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE - GRAPH_TOOLBAR_HEIGHT;

// Until the loader has reported its total, the objects are partial too.
const isInvestigationLoading = ({ loadingCurrent, loadingTotal }: GraphState) => (
  loadingTotal === undefined || (loadingCurrent ?? 0) < loadingTotal
);

interface InvestigationMatrixProps {
  settings: InvestigationMatrixSettings;
  onSettingsChange: InvestigationMatrixSettingsChange;
  /** The matrix filters of the investigation, held with the settings: they act on the scores, never on the graph. */
  filters: InvestigationMatrixFilters;
  onFiltersChange: (change: Partial<InvestigationMatrixFilters>) => void;
  onFiltersClear: () => void;
  /** Name of the image exported from the toolbar. */
  exportName: string;
}

interface InvestigationMatrixContentProps extends InvestigationMatrixProps {
  queryRef: PreloadedQuery<AttackPatternsMatrixQuery>;
  rawObjects: ObjectToParse[];
}

const InvestigationMatrixContent = ({
  queryRef,
  rawObjects,
  settings,
  onSettingsChange,
  filters,
  onFiltersChange,
  onFiltersClear,
  exportName,
}: InvestigationMatrixContentProps) => {
  const { t_i18n } = useFormatter();

  // Kill chains, the "not shown" note and the matrix all read this single query result.
  const { attackPatternsMatrix } = usePreloadedFragment<AttackPatternsMatrixQuery, AttackPatternsMatrixColumns_data$key>({
    queryDef: attackPatternsMatrixQuery,
    fragmentDef: attackPatternsMatrixColumnsFragment,
    queryRef,
  });
  const phases = attackPatternsMatrix?.attackPatternsOfPhases ?? NO_PHASES;
  const { killChains, killChain, techniqueIds, techniques } = useMatrixKillChain(phases, settings.killChain);
  const { attackPatternIdsToOverlap, onSecurityPlatformsChange } = useSecurityPosture(settings.securityPlatforms, onSettingsChange);

  // The attack patterns and the "not shown" note are those of the whole investigation: only the scores are filtered.
  const attackPatterns = useMemo(() => getInvestigationAttackPatterns(rawObjects), [rawObjects]);
  const unplacedAttackPatterns = useMemo(
    () => getUnplacedAttackPatterns(attackPatterns, techniqueIds),
    [attackPatterns, techniqueIds],
  );
  const isEmpty = attackPatterns.length === 0;

  const links = useMemo(() => getScoringLinks(rawObjects), [rawObjects]);
  const scores = useMatrixScores({ links, filters, attackPatterns, techniqueIds, techniques, heatmapSelected: settings.heatmap });
  const filterControls = useMatrixFilterControls({ links, filters, onFiltersChange, onFiltersClear });

  return (
    <>
      {/* Room for the time range panel, which grows the toolbar over the view: kept out of the exported box. */}
      <div style={{ height: '100%', boxSizing: 'border-box', paddingBottom: filterControls.timeRangeOpen ? TIME_RANGE_PANEL_HEIGHT : undefined }}>
        {/* A column as high as the view; the toolbar is docked under it, out of the image and the PDF. */}
        <div
          id={INVESTIGATION_MATRIX_EXPORT_ID}
          style={{ padding: '16px 24px', height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column' }}
        >
          {/* The toolbar shows the legend on screen; this copy is only drawn in the exported image and PDF.
              Rendered only with the heatmap on: the capture shows it, and an empty one would leave its margin there. */}
          {scores.heatmapOn && (
            <div {...{ [EXPORT_ONLY_ATTRIBUTE]: '' }} hidden style={{ marginBottom: 16 }}>
              <HeatmapLegend max={scores.heatMax} />
            </div>
          )}
          {isEmpty ? (
            <Text variant="content-compact" style={{ marginTop: 40, textAlign: 'center' }}>
              {t_i18n('Add attack patterns to the graph view to visualise them here')}
            </Text>
          ) : (
            <div style={{ flex: 1, minHeight: 0 }}>
              <AttackPatternsMatrix
                variant="investigation"
                queryRef={queryRef}
                attackPatterns={attackPatterns}
                selectedKillChain={killChain}
                isModeOnlyActive={settings.onlyUsed}
                attackPatternIdsToOverlap={attackPatternIdsToOverlap}
                entityType="Investigation"
                cellDecorations={scores.cellDecorations}
              />
            </div>
          )}
        </div>
      </div>
      <InvestigationMatrixToolbar
        outsideKillChain={unplacedAttackPatterns}
        killChains={killChains}
        killChain={killChain}
        settings={settings}
        onSettingsChange={onSettingsChange}
        onSecurityPlatformsChange={onSecurityPlatformsChange}
        isEmpty={isEmpty}
        hasScores={scores.hasScores}
        heatmapOn={scores.heatmapOn}
        heatMax={scores.heatMax}
        heatmapDisabledReason={scores.heatmapDisabledReason}
        exportName={exportName}
        filterActions={filterControls.actions}
        timeRangePanel={filterControls.timeRangePanel}
      />
    </>
  );
};

// Always visible while loading, unlike the graph's alert, which hides itself at 0 and after a delay.
const InvestigationMatrixProgress = ({ graphState: { loadingCurrent, loadingTotal } }: { graphState: GraphState }) => {
  const { t_i18n } = useFormatter();
  return (
    <div role="status" style={{ padding: '16px 24px' }}>
      <Text variant="content-compact">
        {t_i18n('Data fetched:')} <span>{loadingCurrent ?? 0} / {loadingTotal ?? '-'}</span>
      </Text>
    </div>
  );
};

const InvestigationMatrix = ({ settings, onSettingsChange, filters, onFiltersChange, onFiltersClear, exportName }: InvestigationMatrixProps) => {
  const { rawObjects, graphState } = useGraphContext();
  const queryRef = useQueryLoading<AttackPatternsMatrixQuery>(attackPatternsMatrixQuery, {});

  // Never render, nor score, from a partially loaded investigation.
  if (isInvestigationLoading(graphState)) {
    return <InvestigationMatrixProgress graphState={graphState} />;
  }

  return (
    <ErrorBoundary>
      <Suspense fallback={<Loader />}>
        {queryRef && (
          <InvestigationMatrixContent
            queryRef={queryRef}
            rawObjects={rawObjects}
            settings={settings}
            onSettingsChange={onSettingsChange}
            filters={filters}
            onFiltersChange={onFiltersChange}
            onFiltersClear={onFiltersClear}
            exportName={exportName}
          />
        )}
      </Suspense>
    </ErrorBoundary>
  );
};

export default InvestigationMatrix;
