import React, { Suspense, useEffect, useMemo, useState } from 'react';
import { PreloadedQuery } from 'react-relay';
import * as R from 'ramda';
import { LocalFireDepartmentOutlined } from '@mui/icons-material';
import {
  Icon,
  IconButton,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  Text,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import AttackPatternsMatrix, { attackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import { attackPatternsMatrixColumnsFragment } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import { AttackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import { AttackPatternsMatrixColumns_data$key } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixColumns_data.graphql';
import EntitySelect, { EntityOption } from '@components/common/form/EntitySelect';
import useShouldCoverOverlap from '@components/common/stix_domain_objects/useShouldCoverOverlap';
import { ErrorBoundary } from '@components/Error';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import { GraphState } from '../../../../../components/graph/graph.types';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import Loader from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
import { MESSAGING$ } from '../../../../../relay/environment';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import usePreloadedFragment from '../../../../../utils/hooks/usePreloadedFragment';
import { INVESTIGATION_MATRIX_EXPORT_ID } from '../InvestigationViewSwitcher';
import { trackInvestigationUsage, useTrackInvestigationUsageOnMount } from '../useInvestigationUsageEvent';
import { analyseTechniqueUsage } from './ttpAnalyser';
import { computeHeatScale } from './heatScale';
import { buildCellDecorations, MatrixTechniqueNode } from './buildCellDecorations';
import HeatmapLegend from './HeatmapLegend';
import {
  formatNameList,
  getInvestigationAttackPatterns,
  getKillChainTechniqueIds,
  getUnplacedAttackPatterns,
  hasActiveGraphFilters,
  MatrixPhase,
  pickDefaultKillChain,
} from './investigationMatrixUtils';

const MAX_LISTED_NAMES = 10;
const NO_PHASES: ReadonlyArray<MatrixPhase> = [];

// Until the loader has reported its total, the objects are partial too.
const isInvestigationLoading = ({ loadingCurrent, loadingTotal }: GraphState) => (
  loadingTotal === undefined || (loadingCurrent ?? 0) < loadingTotal
);

interface InvestigationMatrixContentProps {
  investigationId: string;
  queryRef: PreloadedQuery<AttackPatternsMatrixQuery>;
  rawObjects: ObjectToParse[];
  graphState: GraphState;
}

const InvestigationMatrixContent = ({ investigationId, queryRef, rawObjects, graphState }: InvestigationMatrixContentProps) => {
  const { t_i18n } = useFormatter();
  const [selectedKillChain, setSelectedKillChain] = useState<string>();
  const [isModeOnlyActive, setIsModeOnlyActive] = useState(false);
  const [isHeatmapSelected, setIsHeatmapSelected] = useState(false);
  const [selectedSecurityPlatforms, setSelectedSecurityPlatforms] = useState<EntityOption[]>([]);
  const { attackPatternIdsToOverlap, setSecurityPlatformIds, error: postureError } = useShouldCoverOverlap();

  // Kill chains, the "can't be placed" note and the matrix all read this single query result.
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
    setSelectedSecurityPlatforms(platforms);
    await setSecurityPlatformIds(platforms.map(({ value }) => value));
  };

  const onlyUsedLabel = isModeOnlyActive
    ? t_i18n('Display the whole matrix')
    : t_i18n('Display only used techniques');

  const handleHeatmapToggle = () => {
    if (!isHeatmapOn) trackInvestigationUsage(investigationId, 'HEATMAP_ENABLED');
    setIsHeatmapSelected(!isHeatmapOn);
  };

  const heatmapLabel = t_i18n('Displays heat map of attack pattern use');
  const heatmapToggle = (
    <IconButton
      variant="default"
      priority="tertiary"
      active={isHeatmapOn}
      disabled={!hasScores}
      aria-label={heatmapLabel}
      onClick={handleHeatmapToggle}
      icon={<LocalFireDepartmentOutlined fontSize="small" />}
    />
  );

  return (
    <div id={INVESTIGATION_MATRIX_EXPORT_ID} style={{ padding: '16px 24px' }}>
      <div style={{ display: 'flex', alignItems: 'end', gap: 8 }}>
        <Select value={killChain ?? ''} onValueChange={setSelectedKillChain} disabled={isEmpty}>
          <SelectLabel>{t_i18n('Kill chain :')}</SelectLabel>
          <SelectTrigger aria-label={t_i18n('Kill chain')}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Kill chain')}>
            {killChains.map((killChainName) => (
              <SelectItem key={killChainName} value={killChainName}>
                {killChainName}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Tooltip>
          <TooltipTrigger asChild>
            <IconButton
              variant="default"
              priority="tertiary"
              active={isModeOnlyActive}
              disabled={isEmpty}
              aria-label={onlyUsedLabel}
              onClick={() => setIsModeOnlyActive((value) => !value)}
              icon={<Icon name="eye" />}
            />
          </TooltipTrigger>
          <TooltipContent>{onlyUsedLabel}</TooltipContent>
        </Tooltip>
        {hasScores ? (
          <Tooltip>
            <TooltipTrigger asChild>{heatmapToggle}</TooltipTrigger>
            <TooltipContent>{heatmapLabel}</TooltipContent>
          </Tooltip>
        ) : (
          // A disabled button gets neither focus nor pointer events: this focusable wrapper triggers the tooltip instead.
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={0} style={{ display: 'inline-flex' }}>{heatmapToggle}</span>
            </TooltipTrigger>
            <TooltipContent>{t_i18n('No attack pattern is linked to an entity in this investigation')}</TooltipContent>
          </Tooltip>
        )}
        <div style={{ display: 'flex', minWidth: 300, maxWidth: 500, marginLeft: 'auto' }}>
          <EntitySelect
            multiple
            disabled={isEmpty}
            value={selectedSecurityPlatforms}
            label={t_i18n('Compare with my security posture')}
            types={['SecurityPlatform']}
            onChange={(platforms) => handleSecurityPlatformsChange(platforms as EntityOption[])}
          />
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 8 }}>
        {unplacedAttackPatterns.length > 0 && (
          <Tooltip>
            <TooltipTrigger asChild>
              <Text variant="content-caption" tabIndex={0}>
                {t_i18n(
                  '{count, plural, one {# attack pattern in this investigation isn\'t shown in this kill chain} other {# attack patterns in this investigation aren\'t shown in this kill chain}}',
                  { values: { count: unplacedAttackPatterns.length } },
                )}
              </Text>
            </TooltipTrigger>
            <TooltipContent>
              {formatNameList(unplacedAttackPatterns.map(({ name }) => name), MAX_LISTED_NAMES, t_i18n)}
            </TooltipContent>
          </Tooltip>
        )}
        {hasActiveGraphFilters(graphState) && (
          <Text variant="content-caption">{t_i18n('Graph filters don\'t apply to the matrix')}</Text>
        )}
        {isHeatmapOn && <HeatmapLegend max={heatScale.max} />}
      </div>
      {isEmpty ? (
        <Text variant="content-compact" style={{ marginTop: 40, textAlign: 'center' }}>
          {t_i18n('Add attack patterns to the graph view to visualise them here')}
        </Text>
      ) : (
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
      )}
    </div>
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

const InvestigationMatrix = ({ investigationId }: { investigationId: string }) => {
  // The matrix layer mounts only in matrix view, so this counts a view, loading state included.
  useTrackInvestigationUsageOnMount(investigationId, 'MATRIX_VIEWED');
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
            investigationId={investigationId}
            queryRef={queryRef}
            rawObjects={rawObjects}
            graphState={graphState}
          />
        )}
      </Suspense>
    </ErrorBoundary>
  );
};

export default InvestigationMatrix;
