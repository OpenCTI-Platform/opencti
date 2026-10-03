import React, { Suspense, useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import { Box, Stack, Typography } from '@mui/material';
import { FilterCenterFocusOutlined, RefreshOutlined } from '@mui/icons-material';
import { IconButton, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import AttackPatternsMatrix from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import type { DefenseMatrixMode } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixDefense';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import Card from '../../../../components/common/card/Card';
import Alert from '../../../../components/Alert';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Security from '../../../../utils/Security';
import { SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import { capitalizeFirstLetter } from '../../../../utils/String';
import { DefenseMatrixQuery } from './__generated__/DefenseMatrixQuery.graphql';
import { DefenseMatrixPlatformsQuery } from './__generated__/DefenseMatrixPlatformsQuery.graphql';
import { DefenseMatrixRecomputeMutation } from './__generated__/DefenseMatrixRecomputeMutation.graphql';
import DefenseScopeToolbar from './DefenseScopeToolbar';
import DefenseTechniqueDrawer from './DefenseTechniqueDrawer';
import DefenseTacticsCoverage from './DefenseTacticsCoverage';
import { DefenseLevelsBar, DefenseLevelsLegend } from './DefenseLevelsBar';
import useDefenseScope from './useDefenseScope';
import { ALL_DEFENSE_LAYERS, type DefenseLayersState, type DefenseScopeState, summarizeLevels, toThreatScopeInput } from './defenseMatrix-utils';

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
    }
  }
`;

export const defenseMatrixQuery = graphql`
  query DefenseMatrixQuery($platformIds: [String!], $threatScope: DefenseThreatScope) {
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

export const DefenseMatrixContent = ({ queryRef, scope, layers }: DefenseMatrixContentProps) => {
  const { t_i18n } = useFormatter();
  const { defenseMatrix } = usePreloadedQuery(defenseMatrixQuery, queryRef);
  const [selected, setSelected] = useState<{ id: string; title: string } | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [onlyFocus, setOnlyFocus] = useState(false);
  const [killChain, setKillChain] = useState(DEFAULT_KILL_CHAIN);

  const cells = defenseMatrix?.cells ?? [];
  const cellsById = useMemo(() => new Map(cells.map((cell) => [cell.attack_pattern_id, cell])), [cells]);
  const threatOverlay = scope.threatMode !== 'NONE' && (defenseMatrix?.threats_count ?? 0) > 0;
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
    selectedId: selected?.id,
    onSelect: (id: string) => {
      const cell = cellsById.get(id);
      const title = cell ? `${cell.x_mitre_id ? `[${cell.x_mitre_id}] ` : ''}${cell.name}` : t_i18n('Technique');
      setSelected({ id, title });
    },
  }), [cellsById, layers, threatOverlay, selected?.id]);

  if (!defenseMatrix) {
    return <Alert severity="warning" content={t_i18n('The defense matrix is not available.')} />;
  }

  const overall = summarizeLevels(defenseMatrix.levels);
  const threats = summarizeLevels(defenseMatrix.threat_levels);
  const focusLabel = threatOverlay ? t_i18n('Display only techniques used by threats') : t_i18n('Display only techniques with coverage');

  return (
    <>
      {!defenseMatrix.computed_at && (
        <Alert
          severity="warning"
          content={t_i18n('The defense coverage has not been computed yet. It is computed every night and after relevant changes; an administrator can request a computation now.')}
        />
      )}
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
                <Typography variant="h2" component="p" sx={{ margin: 0 }}>{`${threats.percent}%`}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {t_i18n('{covered} of {total} techniques used by {threats} threats', {
                    values: { covered: threats.covered, total: threats.total, threats: defenseMatrix.threats_count },
                  })}
                </Typography>
                <Box sx={{ marginTop: 1 }}><DefenseLevelsBar levels={defenseMatrix.threat_levels} /></Box>
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
                  size="sm"
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
            <SearchInput variant="thin" onSubmit={setSearchTerm} />
          </Stack>
        )}
      >
        <AttackPatternsMatrix
          attackPatterns={[]}
          handleAdd={() => {}}
          entityType="Defense-Matrix"
          searchTerm={searchTerm}
          selectedKillChain={killChain}
          isModeOnlyActive={onlyFocus}
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
  const { t_i18n, nsdt } = useFormatter();
  const { defensePlatforms, defenseCoverageStatus } = usePreloadedQuery(defenseMatrixPlatformsQuery, queryRef);
  const [recomputeRequested, setRecomputeRequested] = useState(false);
  const [commitRecompute, recomputing] = useApiMutation<DefenseMatrixRecomputeMutation>(defenseMatrixRecomputeMutation, undefined, {
    successMessage: t_i18n('The defense coverage will be recomputed shortly'),
  });
  const pending = recomputeRequested || !!defenseCoverageStatus?.full_computation_requested;
  return (
    <Stack spacing={2}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" flexWrap="wrap" useFlexGap spacing={1}>
        <Typography variant="body2" color="text.secondary" data-testid="defense-matrix-status">
          {defenseCoverageStatus?.computed_at
            ? `${t_i18n('Computed at')} ${nsdt(defenseCoverageStatus.computed_at)}`
            : t_i18n('Not computed yet')}
          {pending ? ` - ${t_i18n('Recomputation requested')}` : ''}
        </Typography>
        <Stack direction="row" spacing={1}>
          <Button variant="secondary" component={Link} to="/dashboard/techniques/defense_gaps">
            {t_i18n('Defense gaps')}
          </Button>
          <Security needs={[SETTINGS_SETCUSTOMIZATION]}>
            <Button
              variant="secondary"
              startIcon={<RefreshOutlined fontSize="small" />}
              disabled={recomputing || pending}
              data-testid="defense-matrix-recompute"
              onClick={() => commitRecompute({ variables: {}, onCompleted: () => setRecomputeRequested(true) })}
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
  const { t_i18n } = useFormatter();
  const [scope, setScope] = useDefenseScope();
  const [layers, setLayers] = useState<DefenseLayersState>(ALL_DEFENSE_LAYERS);
  const platformsQueryRef = useQueryLoading<DefenseMatrixPlatformsQuery>(defenseMatrixPlatformsQuery, {});
  const matrixQueryRef = useQueryLoading<DefenseMatrixQuery>(defenseMatrixQuery, {
    platformIds: scope.platformIds,
    threatScope: toThreatScopeInput(scope),
  });
  return (
    <div data-testid="defense-matrix-page">
      <PageContainer withGap>
        <Breadcrumbs noMargin elements={[{ label: t_i18n('Techniques') }, { label: t_i18n('Defense matrix'), current: true }]} />
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
      </PageContainer>
    </div>
  );
};

export default DefenseMatrix;
