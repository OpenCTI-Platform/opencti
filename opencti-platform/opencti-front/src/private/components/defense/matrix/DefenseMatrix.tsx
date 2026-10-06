import React, { Suspense, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Box, Stack, Typography } from '@mui/material';
import { FilterCenterFocusOutlined, RefreshOutlined } from '@mui/icons-material';
import { Chip, IconButton, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import AttackPatternsMatrix from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import type { DefenseMatrixMode } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixDefense';
import Card from '../../../../components/common/card/Card';
import Alert from '../../../../components/Alert';
import HubFirstUse from '../../common/hub/HubFirstUse';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import { capitalizeFirstLetter } from '../../../../utils/String';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { notifyPayloadErrors } from './defenseMutation-utils';
import { DefenseMatrixQuery } from './__generated__/DefenseMatrixQuery.graphql';
import { DefenseMatrixPlatformsQuery } from './__generated__/DefenseMatrixPlatformsQuery.graphql';
import { DefenseMatrixRecomputeMutation } from './__generated__/DefenseMatrixRecomputeMutation.graphql';
import DefenseScopeToolbar from './DefenseScopeToolbar';
import DefenseTechniqueDrawer from './DefenseTechniqueDrawer';
import DefenseTacticsCoverage from './DefenseTacticsCoverage';
import DefenseValidationDialog from './DefenseValidationDialog';
import DefenseCoverageDashboardButton from './DefenseCoverageDashboardButton';
import { DefenseLevelsBar, DefenseLevelsLegend } from './DefenseLevelsBar';
import useDefenseScope from './useDefenseScope';
import {
  ALL_DEFENSE_LAYERS,
  DEFENSE_LEVEL_DETECTION_AVAILABLE,
  DEFENSE_LEVEL_DETECTION_DEPLOYED,
  DEFENSE_LEVEL_NONE,
  DEFENSE_LEVEL_TELEMETRY,
  DEFENSE_LEVEL_VALIDATED,
  DEFENSE_THREAT_SCOPE_LABELS,
  type DefenseLayersState,
  type DefenseScopeState,
  defenseValidationTargets,
  isThreatOverlayActive,
  scopedDefensePlatforms,
  summarizeLevels,
  toThreatScopeInput,
} from './defenseMatrix-utils';

export const defenseMatrixPlatformsQuery = graphql`
  query DefenseMatrixPlatformsQuery {
    defensePlatforms {
      id
      name
      entity_type
      security_platform_type
    }
    defenseCoverageStatus {
      computed_at
      last_full_computation
      full_computation_requested
      validation_available
    }
  }
`;

export const defenseMatrixQuery = graphql`
  query DefenseMatrixQuery($platformIds: [String!], $threatScope: DefenseThreatScope) {
    defensePlatforms {
      id
      name
    }
    defenseCoverageStatus {
      validation_available
    }
    defenseMatrix(platformIds: $platformIds, threatScope: $threatScope) {
      computed_at
      threats_count
      techniques_count
      levels
      threat_levels
      cells {
        attack_pattern_id
        x_mitre_id
        name
        level
        telemetry
        detection
        validated
        mitigated
        recommended_action
        threats_count
      }
      tactics {
        kill_chain_phase_id
        kill_chain_name
        phase_name
        x_opencti_order
        techniques_count
        levels
        threat_techniques_count
        threat_levels
      }
    }
  }
`;

const defenseMatrixRecomputeMutation = graphql`
  mutation DefenseMatrixRecomputeMutation {
    defenseCoverageRecompute
  }
`;

const DEFAULT_KILL_CHAIN = 'mitre-attack';
const DEFENSE_MATRIX_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/defense-matrix/';
const RECOMPUTE_POLL_INTERVAL = 10000;

const killChainLabel = (chain: string) => {
  if (chain === 'mitre-attack') return 'MITRE ATT&CK';
  if (chain === 'capec') return 'CAPEC';
  if (chain === 'disarm') return 'DISARM';
  return capitalizeFirstLetter(chain);
};

interface DefenseMatrixContentProps {
  queryRef: PreloadedQuery<DefenseMatrixQuery>;
  scope: DefenseScopeState;
  layers: DefenseLayersState;
}

type DefenseCounter = 'validated' | 'deployed' | 'gaps';
const COUNTER_LEVELS: Record<DefenseCounter, number[]> = {
  validated: [DEFENSE_LEVEL_VALIDATED],
  deployed: [DEFENSE_LEVEL_DETECTION_DEPLOYED],
  gaps: [DEFENSE_LEVEL_NONE, DEFENSE_LEVEL_TELEMETRY, DEFENSE_LEVEL_DETECTION_AVAILABLE],
};

export const DefenseMatrixContent = ({ queryRef, scope, layers }: DefenseMatrixContentProps) => {
  const { t_i18n } = useFormatter();
  const { defenseMatrix, defensePlatforms, defenseCoverageStatus } = usePreloadedQuery(defenseMatrixQuery, queryRef);
  const [selected, setSelected] = useState<{ id: string; title: string } | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [onlyFocus, setOnlyFocus] = useState(false);
  const [killChain, setKillChain] = useState(DEFAULT_KILL_CHAIN);
  const [counter, setCounter] = useState<DefenseCounter | null>(null);
  const [validating, setValidating] = useState(false);
  const levelFilter = counter ? COUNTER_LEVELS[counter] : null;

  const cells = defenseMatrix?.cells ?? [];
  const cellsById = useMemo(() => new Map(cells.map((cell) => [cell.attack_pattern_id, cell])), [cells]);
  // A scope matching no threat targets no technique: it never falls back to every technique
  const threatOverlay = isThreatOverlayActive(scope);
  const killChains = useMemo(
    () => Array.from(new Set((defenseMatrix?.tactics ?? []).map((t) => t.kill_chain_name))).sort((a, b) => a.localeCompare(b)),
    [defenseMatrix?.tactics],
  );
  useEffect(() => {
    if (killChains.length > 0 && !killChains.includes(killChain)) {
      setKillChain(killChains.includes(DEFAULT_KILL_CHAIN) ? DEFAULT_KILL_CHAIN : killChains[0]);
    }
  }, [killChains]);

  const defense: DefenseMatrixMode = useMemo(() => ({
    cells: cellsById,
    layers,
    threatOverlay,
    levelFilter,
    selectedId: selected?.id,
    onSelect: (id: string) => {
      const cell = cellsById.get(id);
      const title = cell ? `${cell.x_mitre_id ? `[${cell.x_mitre_id}] ` : ''}${cell.name}` : t_i18n('Technique');
      setSelected({ id, title });
    },
  }), [cellsById, layers, threatOverlay, levelFilter, selected?.id]);

  if (!defenseMatrix) {
    return <Alert severity="warning" content={t_i18n('The defense matrix is not available.')} />;
  }
  if (defenseMatrix.computed_at && defenseMatrix.techniques_count === 0) {
    return (
      <HubFirstUse
        action={(
          <Button component={Link} to="/dashboard/integrations/available" data-testid="defense-matrix-first-use-import">
            {t_i18n('Import MITRE ATT&CK')}
          </Button>
        )}
        documentationUrl={DEFENSE_MATRIX_DOCUMENTATION_URL}
      />
    );
  }

  const overall = summarizeLevels(defenseMatrix.levels);
  const threats = summarizeLevels(defenseMatrix.threat_levels);
  const focusLabel = threatOverlay ? t_i18n('Display only techniques used by threats') : t_i18n('Display only techniques with coverage');
  const levels = defenseMatrix.levels;
  const counts: Record<DefenseCounter, number> = {
    validated: levels[DEFENSE_LEVEL_VALIDATED] ?? 0,
    deployed: levels[DEFENSE_LEVEL_DETECTION_DEPLOYED] ?? 0,
    gaps: COUNTER_LEVELS.gaps.reduce((sum, level) => sum + (levels[level] ?? 0), 0),
  };
  const counterLabels: Record<DefenseCounter, string> = {
    validated: t_i18n('{count, plural, one {# validated} other {# validated}}', { values: { count: counts.validated } }),
    deployed: t_i18n('{count, plural, one {# deployed} other {# deployed}}', { values: { count: counts.deployed } }),
    gaps: t_i18n('{count, plural, one {# gap} other {# gaps}}', { values: { count: counts.gaps } }),
  };
  // A saved platform that was deleted or is no longer visible is left out, as the matrix itself does
  const scopedPlatforms = scopedDefensePlatforms(scope.platformIds, defensePlatforms);
  const threatScopeLabel = scope.threatMode === 'SELECTED'
    ? t_i18n('{count, plural, one {# selected threat} other {# selected threats}}', { values: { count: scope.threats.length } })
    : t_i18n(DEFENSE_THREAT_SCOPE_LABELS[scope.threatMode]);
  const { targets, deferred: deferredValidationTargets } = defenseValidationTargets(cells, threatOverlay);
  const validationTargets = targets.map((cell) => ({ id: cell.attack_pattern_id, name: cell.name, x_mitre_id: cell.x_mitre_id }));
  let emptyOverlayMessage: string | null = null;
  if (threatOverlay && threats.total === 0) {
    emptyOverlayMessage = defenseMatrix.threats_count === 0
      ? t_i18n('No threat matches this scope: change the selected threats or the filters.')
      : t_i18n('The threats of this scope use no technique of the matrix: change the selected threats or the filters.');
  }
  let validationUnavailableReason: string | null = null;
  if (validationTargets.length === 0) {
    validationUnavailableReason = emptyOverlayMessage ?? t_i18n('Every technique of this scope is already validated.');
  }

  return (
    <>
      {!defenseMatrix.computed_at && (
        <Alert
          severity="warning"
          content={t_i18n('The defense coverage has not been computed yet. It is computed every night and after relevant changes; an administrator can request a computation now.')}
        />
      )}
      <Card>
        <Stack direction="row" alignItems="center" justifyContent="space-between" flexWrap="wrap" useFlexGap spacing={2} data-testid="defense-matrix-header">
          <Stack spacing={1}>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap aria-label={t_i18n('Scope')}>
              {scopedPlatforms.length === 0
                ? <Chip label={t_i18n('All security platforms')} />
                : scopedPlatforms.map((platform) => <Chip key={platform.id} label={platform.name} />)}
              <Chip label={threatScopeLabel} />
            </Stack>
            <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" useFlexGap role="group" aria-label={t_i18n('Filter the matrix by defense level')}>
              {(Object.keys(COUNTER_LEVELS) as DefenseCounter[]).map((key, index) => (
                <React.Fragment key={key}>
                  {index > 0 && <Typography variant="body2" color="text.secondary" aria-hidden>-</Typography>}
                  <Button
                    variant={counter === key ? 'primary' : 'tertiary'}
                    size="small"
                    aria-pressed={counter === key}
                    data-testid={`defense-matrix-counter-${key}`}
                    onClick={() => setCounter(counter === key ? null : key)}
                  >
                    {counterLabels[key]}
                  </Button>
                </React.Fragment>
              ))}
            </Stack>
          </Stack>
          {defenseCoverageStatus?.validation_available && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <Stack spacing={0.5} alignItems="flex-end">
                <Button
                  disabled={validationTargets.length === 0}
                  onClick={() => setValidating(true)}
                  aria-describedby={validationUnavailableReason ? 'defense-matrix-validate-reason' : undefined}
                  data-testid="defense-matrix-validate-gaps"
                >
                  {t_i18n('Validate the gaps')}
                </Button>
                {validationUnavailableReason && (
                  <Typography
                    id="defense-matrix-validate-reason"
                    variant="caption"
                    color="text.secondary"
                    component="p"
                    sx={{ margin: 0, textAlign: 'right' }}
                    data-testid="defense-matrix-validate-reason"
                  >
                    {validationUnavailableReason}
                  </Typography>
                )}
              </Stack>
            </Security>
          )}
        </Stack>
      </Card>
      <DefenseValidationDialog
        open={validating}
        onClose={() => setValidating(false)}
        techniques={validationTargets}
        deferredCount={deferredValidationTargets}
        platforms={scopedPlatforms}
        threats={scope.threatMode === 'SELECTED' ? scope.threats : []}
      />
      <Card title={t_i18n('Defense coverage')}>
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 2fr' }, gap: 4 }}>
          <Stack spacing={2}>
            <Box data-testid="defense-overall-coverage">
              <Typography variant="h1" component="p" sx={{ margin: 0 }}>{`${overall.percent}%`}</Typography>
              <Typography variant="body2" color="text.secondary">
                {t_i18n('{covered} of {total} techniques with a deployed or validated detection', { values: { covered: overall.covered, total: overall.total } })}
              </Typography>
              <Box sx={{ marginTop: 1 }}><DefenseLevelsBar levels={defenseMatrix.levels} /></Box>
            </Box>
            {threatOverlay && (
              <Box data-testid="defense-threat-coverage">
                {emptyOverlayMessage ? (
                  <Typography variant="body2" color="text.secondary" data-testid="defense-threat-coverage-empty">
                    {emptyOverlayMessage}
                  </Typography>
                ) : (
                  <>
                    <Typography variant="h2" component="p" sx={{ margin: 0 }}>{`${threats.percent}%`}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      {t_i18n('{covered} of {total} techniques used by {threats} threats', {
                        values: { covered: threats.covered, total: threats.total, threats: defenseMatrix.threats_count },
                      })}
                    </Typography>
                    <Box sx={{ marginTop: 1 }}><DefenseLevelsBar levels={defenseMatrix.threat_levels} /></Box>
                  </>
                )}
              </Box>
            )}
            <DefenseLevelsLegend />
          </Stack>
          <Box>
            <Typography variant="h4" gutterBottom>
              {threatOverlay ? t_i18n('Coverage by tactic against the threats') : t_i18n('Coverage by tactic')}
            </Typography>
            <DefenseTacticsCoverage tactics={defenseMatrix.tactics} threatsOnly={threatOverlay} killChainName={killChain} />
          </Box>
        </Box>
      </Card>
      <Card
        title={t_i18n('Matrix')}
        action={(
          <Stack direction="row" spacing={1} alignItems="center">
            <Tooltip>
              <TooltipTrigger asChild>
                <IconButton
                  priority="tertiary"
                  active={onlyFocus}
                  aria-label={focusLabel}
                  aria-pressed={onlyFocus}
                  data-testid="defense-matrix-focus"
                  onClick={() => setOnlyFocus((value) => !value)}
                  icon={<FilterCenterFocusOutlined fontSize="small" />}
                />
              </TooltipTrigger>
              <TooltipContent>{focusLabel}</TooltipContent>
            </Tooltip>
            {killChains.length > 1 && (
              <Select value={killChain} onValueChange={setKillChain}>
                <SelectTrigger aria-label={t_i18n('Kill chain')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent aria-label={t_i18n('Kill chain')}>
                  {killChains.map((chain) => (
                    <SelectItem key={chain} value={chain}>{killChainLabel(chain)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
            <SearchInput onSubmit={setSearchTerm} />
          </Stack>
        )}
      >
        <AttackPatternsMatrix
          attackPatterns={[]}
          handleAdd={() => {}}
          entityType="Defense-Matrix"
          searchTerm={searchTerm}
          selectedKillChain={killChain}
          isModeOnlyActive={onlyFocus || levelFilter !== null}
          inPaper
          defense={defense}
        />
      </Card>
      <DefenseTechniqueDrawer
        attackPatternId={selected?.id ?? null}
        title={selected?.title ?? ''}
        scope={scope}
        onClose={() => setSelected(null)}
      />
    </>
  );
};

const DefenseMatrixStatus = ({ queryRef, scope, onScopeChange, layers, onLayersChange }: {
  queryRef: PreloadedQuery<DefenseMatrixPlatformsQuery>;
  scope: DefenseScopeState;
  onScopeChange: (scope: DefenseScopeState) => void;
  layers: DefenseLayersState;
  onLayersChange: (layers: DefenseLayersState) => void;
}) => {
  const { t_i18n, fldt, rd } = useFormatter();
  const { defensePlatforms, defenseCoverageStatus } = usePreloadedQuery(defenseMatrixPlatformsQuery, queryRef);
  const [recomputeRequested, setRecomputeRequested] = useState(false);
  const [commitRecompute, recomputing] = useApiMutation<DefenseMatrixRecomputeMutation>(defenseMatrixRecomputeMutation);
  const pending = recomputeRequested || !!defenseCoverageStatus?.full_computation_requested;
  useEffect(() => {
    if (!pending) return undefined;
    // The status query shares the Relay store: polling it re-renders this component once the manager is done
    const interval = setInterval(() => {
      fetchQuery<DefenseMatrixPlatformsQuery>(defenseMatrixPlatformsQuery, {}, { fetchPolicy: 'network-only' })
        .toPromise()
        .then((data) => {
          const status = data?.defenseCoverageStatus;
          if (status && !status.full_computation_requested) {
            setRecomputeRequested(false);
            return fetchQuery<DefenseMatrixQuery>(
              defenseMatrixQuery,
              { platformIds: scope.platformIds, threatScope: toThreatScopeInput(scope) },
              { fetchPolicy: 'network-only' },
            ).toPromise();
          }
          return undefined;
        })
        // A failed poll is retried at the next tick
        .catch(() => undefined);
    }, RECOMPUTE_POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [pending, scope]);
  const requestRecompute = () => commitRecompute({
    variables: {},
    onCompleted: (response, errors) => {
      if (notifyPayloadErrors(errors) || !response.defenseCoverageRecompute) return;
      MESSAGING$.notifySuccess(t_i18n('The defense coverage will be recomputed shortly'));
      setRecomputeRequested(true);
    },
  });
  return (
    <Stack spacing={2}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" flexWrap="wrap" useFlexGap spacing={1}>
        <Stack direction="row" spacing={1} alignItems="center" data-testid="defense-matrix-status">
          {defenseCoverageStatus?.computed_at ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <Typography variant="body2" color="text.secondary" tabIndex={0} sx={{ cursor: 'help' }}>
                  {t_i18n('Computed {date}', { values: { date: rd(defenseCoverageStatus.computed_at) } })}
                </Typography>
              </TooltipTrigger>
              <TooltipContent>{fldt(defenseCoverageStatus.computed_at)}</TooltipContent>
            </Tooltip>
          ) : (
            <Typography variant="body2" color="text.secondary">{t_i18n('Not computed yet')}</Typography>
          )}
          {pending && <Chip label={t_i18n('Recomputation requested')} severity="info" data-testid="defense-matrix-recompute-pending" />}
        </Stack>
        <Stack direction="row" spacing={1} alignItems="center">
          <DefenseCoverageDashboardButton />
          <Security needs={[SETTINGS_SETCUSTOMIZATION]}>
            <Button
              variant="secondary"
              startIcon={<RefreshOutlined fontSize="small" />}
              disabled={recomputing || pending}
              data-testid="defense-matrix-recompute"
              onClick={requestRecompute}
            >
              {t_i18n('Recompute')}
            </Button>
          </Security>
        </Stack>
      </Stack>
      <DefenseScopeToolbar
        platforms={defensePlatforms}
        scope={scope}
        onScopeChange={onScopeChange}
        layers={layers}
        onLayersChange={onLayersChange}
      />
    </Stack>
  );
};

const DefenseMatrix = () => {
  const [scope, setScope] = useDefenseScope();
  const [layers, setLayers] = useState<DefenseLayersState>(ALL_DEFENSE_LAYERS);
  const platformsQueryRef = useQueryLoading<DefenseMatrixPlatformsQuery>(defenseMatrixPlatformsQuery, {});
  const matrixQueryRef = useQueryLoading<DefenseMatrixQuery>(defenseMatrixQuery, {
    platformIds: scope.platformIds,
    threatScope: toThreatScopeInput(scope),
  });
  return (
    <Stack spacing={3} data-testid="defense-matrix-tab">
      {platformsQueryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <DefenseMatrixStatus
            queryRef={platformsQueryRef}
            scope={scope}
            onScopeChange={setScope}
            layers={layers}
            onLayersChange={setLayers}
          />
        </Suspense>
      )}
      {matrixQueryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <DefenseMatrixContent queryRef={matrixQueryRef} scope={scope} layers={layers} />
        </Suspense>
      )}
    </Stack>
  );
};

export default DefenseMatrix;
