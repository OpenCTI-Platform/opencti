import React, { Suspense, useEffect, useMemo, useState } from 'react';
import { PreloadedQuery } from 'react-relay';
import * as R from 'ramda';
import { Text } from '@filigran/design-system';
import AttackPatternsMatrix, { attackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import { attackPatternsMatrixColumnsFragment } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import { AttackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import { AttackPatternsMatrixColumns_data$key } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixColumns_data.graphql';
import type { EntityOption } from '@components/common/form/EntitySelect';
import useShouldCoverOverlap from '@components/common/stix_domain_objects/useShouldCoverOverlap';
import { ErrorBoundary } from '@components/Error';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import type { GraphState } from '../../../../../components/graph/graph.types';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import GraphToolbarTimeRange from '../../../../../components/graph/components/GraphToolbarTimeRange';
import { GRAPH_TOOLBAR_HEIGHT, GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE } from '../../../../../components/graph/utils/graphFraming';
import { computeTimeRangeInterval, computeTimeRangeValues, countTimeRangeFilters, type GraphTimeRange } from '../../../../../components/graph/utils/graphTimeRange';
import Loader from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
import { MESSAGING$ } from '../../../../../relay/environment';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import usePreloadedFragment from '../../../../../utils/hooks/usePreloadedFragment';
import { INVESTIGATION_MATRIX_EXPORT_ID } from '../InvestigationViewSwitcher';
import { analyseTechniqueUsage } from './ttpAnalyser';
import { computeHeatScale } from './heatScale';
import { buildCellDecorations, MatrixTechniqueNode } from './buildCellDecorations';
import HeatmapLegend from './HeatmapLegend';
import InvestigationMatrixToolbar from './InvestigationMatrixToolbar';
import { EXPORT_ONLY_ATTRIBUTE } from './prepareMatrixCapture';
import { getInvestigationAttackPatterns, getKillChainTechniqueIds, getUnplacedAttackPatterns, MatrixPhase, pickDefaultKillChain } from './investigationMatrixUtils';
import type { InvestigationMatrixSettings, InvestigationMatrixSettingsChange } from './investigationMatrixSettings';
import { filterMatrixObjects, getMatrixFilterOptions, hasActiveMatrixFilters, type InvestigationMatrixFilters } from './matrixFilters';
import { matrixTimeRangeInterval, useInvestigationMatrixFilterActions } from './useInvestigationMatrixFilterActions';

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
  const {
    killChain: selectedKillChain,
    onlyUsed: isModeOnlyActive,
    heatmap: isHeatmapSelected,
    securityPlatforms: selectedSecurityPlatforms,
  } = settings;
  const { attackPatternIdsToOverlap, setSecurityPlatformIds, error: postureError } = useShouldCoverOverlap();

  useEffect(() => {
    // Back from the graph view: the posture marks of the platforms chosen before are looked up again.
    if (selectedSecurityPlatforms.length > 0) {
      setSecurityPlatformIds(selectedSecurityPlatforms.map(({ value }) => value));
    }
  }, []);

  // Kill chains, the "not shown" note and the matrix all read this single query result.
  const { attackPatternsMatrix } = usePreloadedFragment<AttackPatternsMatrixQuery, AttackPatternsMatrixColumns_data$key>({
    queryDef: attackPatternsMatrixQuery,
    fragmentDef: attackPatternsMatrixColumnsFragment,
    queryRef,
  });
  const phases = attackPatternsMatrix?.attackPatternsOfPhases ?? NO_PHASES;
  const killChains = useMemo(
    () => R.uniq(phases.map((phase) => phase.kill_chain_name)).sort((a, b) => a.localeCompare(b)),
    [phases],
  );
  const killChain = selectedKillChain && killChains.includes(selectedKillChain)
    ? selectedKillChain
    : pickDefaultKillChain(killChains);

  const attackPatterns = useMemo(() => getInvestigationAttackPatterns(rawObjects), [rawObjects]);
  const killChainTechniqueIds = useMemo(() => getKillChainTechniqueIds(phases, killChain ?? ''), [phases, killChain]);
  const unplacedAttackPatterns = useMemo(
    () => getUnplacedAttackPatterns(attackPatterns, killChainTechniqueIds),
    [attackPatterns, killChainTechniqueIds],
  );
  const isEmpty = attackPatterns.length === 0;

  // Only the scores read the filtered links: the attack patterns and the note above stay those of the whole investigation.
  const filteredObjects = useMemo(() => filterMatrixObjects(rawObjects, filters), [rawObjects, filters]);
  // The scale comes only from the selected kill chain.
  const usage = useMemo(() => analyseTechniqueUsage(filteredObjects), [filteredObjects]);
  const heatScale = useMemo(() => computeHeatScale(usage, killChainTechniqueIds), [usage, killChainTechniqueIds]);
  const hasScores = !isEmpty && heatScale.max > 0;
  // The filters are blamed only when clearing them would bring scores back in this kill chain: not when only
  // stale ids are stored, nor when the kill chain itself has no score.
  const hasUnfilteredScores = useMemo(() => {
    if (isEmpty || hasScores || !hasActiveMatrixFilters(filters)) return false;
    const unfilteredUsage = filteredObjects === rawObjects ? usage : analyseTechniqueUsage(rawObjects);
    return computeHeatScale(unfilteredUsage, killChainTechniqueIds).max > 0;
  }, [isEmpty, hasScores, filters, filteredObjects, rawObjects, usage, killChainTechniqueIds]);
  const heatmapDisabledReason = hasUnfilteredScores
    ? t_i18n('No attack pattern is left linked to an entity with these filters')
    : undefined;

  const [timeRangeOpen, setTimeRangeOpen] = useState(false);
  const filterOptions = useMemo(() => getMatrixFilterOptions(rawObjects, t_i18n('None')), [rawObjects]);
  // Computed once for the panel and the badge: without any dated link, the range is set from now.
  const timeRange = useMemo<GraphTimeRange>(() => {
    const interval = computeTimeRangeInterval(filterOptions.datedLinks);
    return { interval, values: computeTimeRangeValues(interval, filterOptions.datedLinks) };
  }, [filterOptions]);
  const filterActions = useInvestigationMatrixFilterActions({
    options: filterOptions,
    timeRange,
    filters,
    onChange: onFiltersChange,
    onClear: onFiltersClear,
    timeRangeOpen,
    onToggleTimeRange: () => setTimeRangeOpen((open) => !open),
  });
  // The whole range is stored as no range at all, so that it neither counts as a filter nor needs clearing.
  // The slider snaps its ends to its 30-minute steps when it mounts and reports them: an end snapped off
  // the full range is still the whole range, and an unchanged range is not written again.
  const handleTimeRangeChange = (interval: [Date, Date]) => {
    const next: [string, string] | undefined = countTimeRangeFilters(timeRange.interval, interval) === 0
      ? undefined
      : [interval[0].toISOString(), interval[1].toISOString()];
    const current = filters.timeRange;
    if (next?.[0] === current?.[0] && next?.[1] === current?.[1]) return;
    onFiltersChange({ timeRange: next });
  };
  // A kill chain without scores turns the heatmap off without forgetting the user's choice.
  const isHeatmapOn = isHeatmapSelected && hasScores;
  const killChainTechniques = useMemo(() => {
    const byId = new Map<string, MatrixTechniqueNode>();
    phases
      .filter((phase) => phase.kill_chain_name === killChain)
      .forEach((phase) => (phase.attackPatterns ?? []).forEach((technique) => byId.set(technique.attack_pattern_id, technique)));
    return Array.from(byId.values());
  }, [phases, killChain]);
  const investigationIds = useMemo(() => new Set(attackPatterns.map(({ id }) => id)), [attackPatterns]);
  // Without any score, cells render exactly as in US.1: no decoration at all.
  const cellDecorations = useMemo(
    () => (hasScores
      ? buildCellDecorations({ usage, scale: heatScale, techniques: killChainTechniques, investigationIds, heatmapOn: isHeatmapOn, t: t_i18n })
      : undefined),
    [hasScores, usage, heatScale, killChainTechniques, investigationIds, isHeatmapOn],
  );

  useEffect(() => {
    // Once per failed lookup: the matrix keeps rendering, without posture marks.
    if (postureError) MESSAGING$.notifyError(t_i18n('The security posture could not be loaded'));
  }, [postureError]);

  const handleSecurityPlatformsChange = async (platforms: EntityOption[]) => {
    onSettingsChange({ securityPlatforms: platforms });
    await setSecurityPlatformIds(platforms.map(({ value }) => value));
  };

  return (
    <>
      {/* Room for the time range panel, which grows the toolbar over the view: kept out of the exported box. */}
      <div style={{ height: '100%', boxSizing: 'border-box', paddingBottom: timeRangeOpen ? TIME_RANGE_PANEL_HEIGHT : undefined }}>
        {/* A column as high as the view; the toolbar is docked under it, out of the image and the PDF. */}
        <div
          id={INVESTIGATION_MATRIX_EXPORT_ID}
          style={{ padding: '16px 24px', height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column' }}
        >
          {/* The toolbar shows the legend on screen; this copy is only drawn in the exported image and PDF.
              Rendered only with the heatmap on: the capture shows it, and an empty one would leave its margin there. */}
          {isHeatmapOn && (
            <div {...{ [EXPORT_ONLY_ATTRIBUTE]: '' }} hidden style={{ marginBottom: 16 }}>
              <HeatmapLegend max={heatScale.max} />
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
                isModeOnlyActive={isModeOnlyActive}
                // The hook gives [] for an empty selection, which would mark every cell: pass ids only once platforms are chosen.
                attackPatternIdsToOverlap={selectedSecurityPlatforms.length > 0 ? attackPatternIdsToOverlap : undefined}
                entityType="Investigation"
                cellDecorations={cellDecorations}
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
        onSecurityPlatformsChange={handleSecurityPlatformsChange}
        isEmpty={isEmpty}
        hasScores={hasScores}
        heatmapOn={isHeatmapOn}
        heatMax={heatScale.max}
        heatmapDisabledReason={heatmapDisabledReason}
        exportName={exportName}
        filterActions={filterActions}
        // Only mounted while shown, as in the graph: its handles would stay reachable from the keyboard.
        timeRangePanel={timeRangeOpen && (
          <GraphToolbarTimeRange
            timeRange={timeRange}
            selectedInterval={matrixTimeRangeInterval(filters)}
            onChange={handleTimeRangeChange}
          />
        )}
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
