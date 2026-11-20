import React, { Suspense, useEffect, useMemo } from 'react';
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

const NO_PHASES: ReadonlyArray<MatrixPhase> = [];

// Until the loader has reported its total, the objects are partial too.
const isInvestigationLoading = ({ loadingCurrent, loadingTotal }: GraphState) => (
  loadingTotal === undefined || (loadingCurrent ?? 0) < loadingTotal
);

interface InvestigationMatrixProps {
  settings: InvestigationMatrixSettings;
  onSettingsChange: InvestigationMatrixSettingsChange;
  /** Name of the image exported from the toolbar. */
  exportName: string;
}

interface InvestigationMatrixContentProps extends InvestigationMatrixProps {
  queryRef: PreloadedQuery<AttackPatternsMatrixQuery>;
  rawObjects: ObjectToParse[];
}

const InvestigationMatrixContent = ({ queryRef, rawObjects, settings, onSettingsChange, exportName }: InvestigationMatrixContentProps) => {
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

  // Scores come from the whole, unfiltered investigation; the scale only from the selected kill chain.
  const usage = useMemo(() => analyseTechniqueUsage(rawObjects), [rawObjects]);
  const heatScale = useMemo(() => computeHeatScale(usage, killChainTechniqueIds), [usage, killChainTechniqueIds]);
  const hasScores = !isEmpty && heatScale.max > 0;
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
      {/* A column as high as the view; the toolbar is docked under it, out of the image and the PDF. */}
      <div
        id={INVESTIGATION_MATRIX_EXPORT_ID}
        style={{ padding: '16px 24px', height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column' }}
      >
        {/* The toolbar shows the legend on screen; this copy is only drawn in the exported image and PDF. */}
        <div {...{ [EXPORT_ONLY_ATTRIBUTE]: '' }} hidden style={{ marginBottom: 16 }}>
          {isHeatmapOn && <HeatmapLegend max={heatScale.max} />}
        </div>
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
        exportName={exportName}
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

const InvestigationMatrix = ({ settings, onSettingsChange, exportName }: InvestigationMatrixProps) => {
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
            exportName={exportName}
          />
        )}
      </Suspense>
    </ErrorBoundary>
  );
};

export default InvestigationMatrix;
