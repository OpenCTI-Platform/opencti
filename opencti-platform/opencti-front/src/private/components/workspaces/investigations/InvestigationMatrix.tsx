import React, { FunctionComponent, useMemo, useState } from 'react';
import Typography from '@mui/material/Typography';
import { Box, FormControl, IconButton, InputLabel, MenuItem, Select, Stack, Tooltip } from '@mui/material';
import { SelectChangeEvent } from '@mui/material/Select';
import { VisibilityOutlined, LocalFireDepartmentOutlined } from '@mui/icons-material';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import * as R from 'ramda';
import { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import { attackPatternsMatrixColumnsFragment } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import { AttackPatternsMatrixColumns_data$key } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixColumns_data.graphql';
import { AttackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import EntitySelect, { EntityOption } from '@components/common/form/EntitySelect';
import { InvestigationMatrixOverlapQuery$data } from './__generated__/InvestigationMatrixOverlapQuery.graphql';
import AttackPatternsMatrix, { AttackPatternsMatrixProps, attackPatternsMatrixQuery } from '../../techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import { HEATMAP_STEP_COLORS, getHeatmapColors } from '../../techniques/attack_patterns/attack_patterns_matrix/attackPatternsHeatmap';
import { ObjectToParse } from '../../../../components/graph/utils/useGraphParser';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import { buildInvestigationMatrixUsage } from './investigationMatrixUsage';
import useInvestigationCoverageMap from './useInvestigationCoverageMap';
import InvestigationMatrixLegend from './InvestigationMatrixLegend';

// Resolve the Attack-Patterns that the selected security platforms declare they
// "should-cover". These ids drive the green tick / red cross overlap indicator
// on each technique cell (see AttackPatternsMatrixShouldCoverIcon).
const investigationMatrixOverlapQuery = graphql`
  query InvestigationMatrixOverlapQuery($types: [String], $count: Int!, $filters: FilterGroup) {
    stixCoreObjects(types: $types, first: $count, filters: $filters) {
      edges {
        node {
          id
          entity_type
        }
      }
    }
  }
`;

interface InvestigationMatrixProps {
  // All objects currently present in the investigation graph.
  objects: ObjectToParse[];
  // A/B testing variant. 'A' is the current control, 'B' is the alternate
  // version being trialled. Currently both render the same matrix; this prop
  // is the hook to diverge the two experiences later.
  variant?: 'A' | 'B';
  // Optional controls (e.g. the graph/matrix view switcher) rendered
  // right-aligned on the matrix toolbar line to save vertical space.
  headerActions?: React.ReactNode;
}

const DEFAULT_KILL_CHAIN = 'mitre-attack';

// Read-only Techniques "Matrix" view for an investigation.
// It only displays the Attack Patterns that are already present in the
// investigation graph (no data is fetched or added from here).
const InvestigationMatrix: FunctionComponent<InvestigationMatrixProps> = ({ objects, variant = 'A', headerActions }) => {
  const { t_i18n } = useFormatter();

  // Matrix view controls.
  const [selectedKillChain, setSelectedKillChain] = useState<string>(DEFAULT_KILL_CHAIN);
  // Investigations focus on used techniques by default, but the user can show the whole matrix.
  const [isModeOnlyActive, setIsModeOnlyActive] = useState<boolean>(true);
  // "Compare with my security posture": selected security platforms and the
  // Attack-Pattern ids they should cover (drives the tick / cross overlay).
  const [selectedSecurityPlatforms, setSelectedSecurityPlatforms] = useState<EntityOption[]>([]);
  const [attackPatternIdsToOverlap, setAttackPatternIdsToOverlap] = useState<string[] | undefined>();
  // Frequency heatmap (US.3) - variant A only. Colours techniques by how many
  // investigation entities use them, on a relative yellow -> red scale.
  const isHeatmapAvailable = variant === 'A';
  const [isHeatmapActive, setIsHeatmapActive] = useState<boolean>(false);

  const attackPatterns = useMemo(
    () => objects.filter((o) => o.entity_type === 'Attack-Pattern'),
    [objects],
  );

  // Which investigation entities use which attack pattern (via `uses` relationships).
  const { usageByAttackPattern, legend } = useMemo(
    () => buildInvestigationMatrixUsage(objects),
    [objects],
  );

  // Entities the user has toggled off in the legend: their markers are hidden
  // from the matrix cells while their relationships remain in the graph.
  const [hiddenEntityIds, setHiddenEntityIds] = useState<Set<string>>(new Set());

  const toggleEntity = (entityId: string) => {
    setHiddenEntityIds((current) => {
      const next = new Set(current);
      if (next.has(entityId)) {
        next.delete(entityId);
      } else {
        next.add(entityId);
      }
      return next;
    });
  };

  // Usage map with the toggled-off entities removed, so only the selected
  // entities' markers are rendered on the technique cells.
  const visibleUsageByAttackPattern = useMemo(() => {
    if (hiddenEntityIds.size === 0) return usageByAttackPattern;
    const filtered = new Map<string, typeof legend>();
    usageByAttackPattern.forEach((entities, attackPatternId) => {
      const visible = entities.filter((entity) => !hiddenEntityIds.has(entity.id));
      if (visible.length > 0) {
        filtered.set(attackPatternId, visible);
      }
    });
    return filtered;
  }, [usageByAttackPattern, hiddenEntityIds]);

  // Frequency score per attack pattern = number of investigation entities that
  // use it (respecting the entity legend toggles). Only entries with a score
  // are kept. The relative colour scale spans min -> max of these scores.
  const { frequencyMap, heatmapScale } = useMemo(() => {
    const counts = new Map<string, number>();
    visibleUsageByAttackPattern.forEach((entities, attackPatternId) => {
      if (entities.length > 0) {
        counts.set(attackPatternId, entities.length);
      }
    });
    const values = [...counts.values()];
    const scale = values.length > 0
      ? { min: Math.min(...values), max: Math.max(...values) }
      : undefined;
    return { frequencyMap: counts, heatmapScale: scale };
  }, [visibleUsageByAttackPattern]);

  // One legend swatch per distinct frequency value present in the dataset, each
  // coloured exactly like the matrix cells with that value. So a single value
  // renders one solid block, two values render a 50/50 split, and so on.
  const heatmapStepColors = useMemo(() => {
    if (!heatmapScale) return [];
    const distinctValues = [...new Set(frequencyMap.values())].sort((a, b) => a - b);
    return distinctValues.map((value) => getHeatmapColors(value, heatmapScale).border);
  }, [frequencyMap, heatmapScale]);

  // Heatmap can only be applied when there is at least one scored technique.
  const heatmapActive = isHeatmapAvailable && isHeatmapActive && heatmapScale !== undefined;

  // Detection/prevention coverage scores from `has-covered` relationships present on the graph.
  const coverageOverlayMap = useInvestigationCoverageMap(objects);

  // Load the full attack patterns matrix to derive the list of available kill chains.
  const matrixData = useLazyLoadQuery<AttackPatternsMatrixQuery>(attackPatternsMatrixQuery, {});
  const { attackPatternsMatrix } = useFragment<AttackPatternsMatrixColumns_data$key>(
    attackPatternsMatrixColumnsFragment,
    matrixData,
  );
  const killChains = useMemo(
    () => R.uniq((attackPatternsMatrix?.attackPatternsOfPhases ?? []).map((a) => a.kill_chain_name))
      .sort((a, b) => a.localeCompare(b)),
    [attackPatternsMatrix],
  );

  // Keep the selected kill chain valid if the default is not available.
  const effectiveKillChain = killChains.length > 0 && !killChains.includes(selectedKillChain)
    ? killChains[0]
    : selectedKillChain;

  const handleKillChainChange = (event: SelectChangeEvent<unknown>) => {
    setSelectedKillChain(event.target.value as string);
  };

  // Fetch the Attack-Patterns "should-covered" by the given security platforms.
  const getAttackPatternIdsToOverlap = async (entityIdsToOverlap: string[]) => {
    if (entityIdsToOverlap.length === 0) return undefined;
    const { stixCoreObjects } = await fetchQuery(
      investigationMatrixOverlapQuery,
      {
        count: 1000,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'entity_type',
              operator: 'eq',
              mode: 'or',
              values: ['Attack-Pattern'],
            },
            {
              key: 'regardingOf',
              operator: 'eq',
              mode: 'and',
              values: [
                {
                  key: 'id',
                  values: entityIdsToOverlap,
                  operator: 'eq',
                  mode: 'or',
                },
                {
                  key: 'relationship_type',
                  values: ['should-cover'],
                  operator: 'eq',
                  mode: 'or',
                },
              ],
            },
          ],
          filterGroups: [],
        },
      },
    ).toPromise() as InvestigationMatrixOverlapQuery$data;
    return stixCoreObjects?.edges?.map(({ node }) => node.id);
  };

  const handleSecurityPlatformsChange = async (newSelectedSecurityPlatforms: EntityOption[]) => {
    setSelectedSecurityPlatforms(newSelectedSecurityPlatforms);
    const entityIds = newSelectedSecurityPlatforms.map(({ value }) => value);
    const attackPatternIds = await getAttackPatternIdsToOverlap(entityIds);
    setAttackPatternIdsToOverlap(attackPatternIds);
  };

  if (attackPatterns.length === 0) {
    return (
      <Box sx={{ paddingTop: 2 }}>
        {headerActions && (
          <Stack direction="row" justifyContent="flex-end" sx={{ paddingInline: 2 }}>
            {headerActions}
          </Stack>
        )}
        <Typography
          variant="body2"
          color="textSecondary"
          style={{ marginTop: 40, textAlign: 'center' }}
        >
          {t_i18n('Add attack patterns to the graph view to visualise them here')}
        </Typography>
      </Box>
    );
  }

  // The matrix is read-only in an investigation: adding techniques is a no-op.
  const noop = (_entity: TargetEntity) => {};

  return (
    <Box data-matrix-variant={variant} sx={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0, paddingTop: 2 }}>
      <Stack direction="row" alignItems="center" gap={1} sx={{ paddingInline: 2, paddingBottom: 1 }}>
        <Stack direction="row" alignItems="center">
          <InputLabel style={{ paddingInlineEnd: 10, marginTop: 1 }}>
            {t_i18n('Kill chain :')}
          </InputLabel>
          <FormControl>
            <Select
              size="small"
              value={effectiveKillChain}
              onChange={handleKillChainChange}
            >
              {killChains.map((killChainName) => (
                <MenuItem key={killChainName} value={killChainName}>
                  {killChainName}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Stack>
        <Tooltip
          title={
            isModeOnlyActive
              ? t_i18n('Display the whole matrix')
              : t_i18n('Display only used techniques')
          }
        >
          <span>
            <IconButton
              color={isModeOnlyActive ? 'secondary' : 'primary'}
              onClick={() => setIsModeOnlyActive((value) => !value)}
            >
              <VisibilityOutlined />
            </IconButton>
          </span>
        </Tooltip>
        {isHeatmapAvailable && (
          <Tooltip title={t_i18n('Displays heat map of attack pattern use')}>
            <span>
              <IconButton
                color={heatmapActive ? 'secondary' : 'primary'}
                disabled={heatmapScale === undefined}
                onClick={() => setIsHeatmapActive((value) => !value)}
              >
                <LocalFireDepartmentOutlined />
              </IconButton>
            </span>
          </Tooltip>
        )}
        {isHeatmapAvailable && heatmapActive && heatmapScale && (
          <Stack direction="row" alignItems="center" gap={0.75}>
            <Typography variant="caption" sx={{ fontWeight: 600 }}>
              {t_i18n('Risk')}
            </Typography>
            <Typography variant="caption">{heatmapScale.min}</Typography>
            <Box sx={{ display: 'flex', height: 10, borderRadius: 5, overflow: 'hidden' }}>
              {(heatmapStepColors.length > 0 ? heatmapStepColors : HEATMAP_STEP_COLORS).map((color, index) => (
                <Box key={`${color}-${index}`} sx={{ width: 20, height: '100%', backgroundColor: color }} />
              ))}
            </Box>
            <Typography variant="caption">{heatmapScale.max}</Typography>
            <Typography variant="caption" noWrap sx={{ marginLeft: 0.5 }}>
              {t_i18n('Technique usage (low \u2192 high)')}
            </Typography>
          </Stack>
        )}
        <FormControl sx={{ display: 'flex', minWidth: 300, maxWidth: 500, marginLeft: 'auto' }}>
          <EntitySelect
            multiple
            variant="outlined"
            size="small"
            value={selectedSecurityPlatforms}
            label={t_i18n('Compare with my security posture')}
            types={['SecurityPlatform']}
            onChange={(newSelectedSecurityPlatforms) => {
              handleSecurityPlatformsChange(newSelectedSecurityPlatforms as EntityOption[]);
            }}
          />
        </FormControl>
        {headerActions}
      </Stack>
      <Box sx={{ flex: 1, minHeight: 0 }}>
        <AttackPatternsMatrix
          attackPatterns={attackPatterns as unknown as AttackPatternsMatrixProps['attackPatterns']}
          entityType="Investigation"
          handleAdd={noop}
          selectedKillChain={effectiveKillChain}
          isModeOnlyActive={isModeOnlyActive}
          // Keep the full sub-technique list so techniques render as collapsible
          // accordions (chevron, collapsed by default) like the security coverage
          // overview matrix, instead of being flattened into leaf cells. In
          // heatmap mode the columns still restrict sub-techniques to used ones.
          onlyActiveSubAttackPatterns={false}
          attackPatternIdsToOverlap={attackPatternIdsToOverlap}
          entityUsageMap={isHeatmapAvailable ? undefined : visibleUsageByAttackPattern}
          coverageOverlayMap={coverageOverlayMap}
          heatmapActive={heatmapActive}
          frequencyMap={frequencyMap}
          heatmapScale={heatmapScale}
          fillContainer
        />
      </Box>
      {!isHeatmapAvailable && (
        <InvestigationMatrixLegend
          legend={legend}
          hasCoverage={coverageOverlayMap.size > 0}
          hiddenEntityIds={hiddenEntityIds}
          onToggleEntity={toggleEntity}
        />
      )}
    </Box>
  );
};

export default InvestigationMatrix;
