import React, { FunctionComponent, useMemo, useState } from 'react';
import Typography from '@mui/material/Typography';
import { Box, FormControl, IconButton, InputLabel, MenuItem, Select, Stack, Tooltip } from '@mui/material';
import { SelectChangeEvent } from '@mui/material/Select';
import { VisibilityOutlined } from '@mui/icons-material';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import * as R from 'ramda';
import { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import { attackPatternsMatrixColumnsFragment } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import { AttackPatternsMatrixColumns_data$key } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixColumns_data.graphql';
import { AttackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import EntitySelect, { EntityOption } from '@components/common/form/EntitySelect';
import { InvestigationMatrixOverlapQuery$data } from './__generated__/InvestigationMatrixOverlapQuery.graphql';
import AttackPatternsMatrix, { AttackPatternsMatrixProps, attackPatternsMatrixQuery } from '../../techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
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
}

const DEFAULT_KILL_CHAIN = 'mitre-attack';

// Read-only Techniques "Matrix" view for an investigation.
// It only displays the Attack Patterns that are already present in the
// investigation graph (no data is fetched or added from here).
const InvestigationMatrix: FunctionComponent<InvestigationMatrixProps> = ({ objects }) => {
  const { t_i18n } = useFormatter();

  // Matrix view controls.
  const [selectedKillChain, setSelectedKillChain] = useState<string>(DEFAULT_KILL_CHAIN);
  // Investigations focus on used techniques by default, but the user can show the whole matrix.
  const [isModeOnlyActive, setIsModeOnlyActive] = useState<boolean>(true);
  // "Compare with my security posture": selected security platforms and the
  // Attack-Pattern ids they should cover (drives the tick / cross overlay).
  const [selectedSecurityPlatforms, setSelectedSecurityPlatforms] = useState<EntityOption[]>([]);
  const [attackPatternIdsToOverlap, setAttackPatternIdsToOverlap] = useState<string[] | undefined>();

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
      <Typography
        variant="body2"
        color="textSecondary"
        style={{ marginTop: 40, textAlign: 'center' }}
      >
        {t_i18n('Add attack patterns to the graph view to visualise them here')}
      </Typography>
    );
  }

  // The matrix is read-only in an investigation: adding techniques is a no-op.
  const noop = (_entity: TargetEntity) => {};

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0, paddingTop: 2 }}>
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
      </Stack>
      <Box sx={{ flex: 1, minHeight: 0 }}>
        <AttackPatternsMatrix
          attackPatterns={attackPatterns as unknown as AttackPatternsMatrixProps['attackPatterns']}
          entityType="Investigation"
          handleAdd={noop}
          selectedKillChain={effectiveKillChain}
          isModeOnlyActive={isModeOnlyActive}
          onlyActiveSubAttackPatterns={isModeOnlyActive}
          attackPatternIdsToOverlap={attackPatternIdsToOverlap}
          entityUsageMap={visibleUsageByAttackPattern}
          coverageOverlayMap={coverageOverlayMap}
          fillContainer
        />
      </Box>
      <InvestigationMatrixLegend
        legend={legend}
        hasCoverage={coverageOverlayMap.size > 0}
        hiddenEntityIds={hiddenEntityIds}
        onToggleEntity={toggleEntity}
      />
    </Box>
  );
};

export default InvestigationMatrix;
