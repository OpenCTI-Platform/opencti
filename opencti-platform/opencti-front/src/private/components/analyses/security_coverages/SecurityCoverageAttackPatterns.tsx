import Typography from '@mui/material/Typography';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import { ViewListOutlined, ViewModuleOutlined, VisibilityOutlined } from '@mui/icons-material';
import FormControl from '@mui/material/FormControl';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import React, { useEffect, useMemo, useState } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import StixCoreRelationshipPopover from '@components/common/stix_core_relationships/StixCoreRelationshipPopover';
import { Box, IconButton, ListItemButton, Stack, Tooltip } from '@mui/material';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import SecurityCoverageScores from '@components/analyses/security_coverages/SecurityCoverageScores';
import { useTheme } from '@mui/styles';
import { InformationOutline } from 'mdi-material-ui';
import SecurityCoverageCoveredList from './SecurityCoverageCoveredList';
import { SecurityCoverageAttackPatternsKillChainPhasesFragment$key } from './__generated__/SecurityCoverageAttackPatternsKillChainPhasesFragment.graphql';
import { SecurityCoverageAttackPatternsFragment$data } from './__generated__/SecurityCoverageAttackPatternsFragment.graphql';
import SecurityCoverageAttackPatternsMatrix from './SecurityCoverageAttackPatternsMatrix';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { capitalizeFirstLetter } from '../../../../utils/String';
import Card from '../../../../components/common/card/Card';
import Alert from '../../../../components/Alert';
import { dedupeCoveredEntities } from './securityCoverageAggregation';

const MAX_ATTACK_PATTERNS = 5000;

const securityCoverageKillChainPhasesFragment = graphql`
  fragment SecurityCoverageAttackPatternsKillChainPhasesFragment on Query {
    allAttackPatterns: attackPatterns(first: 1000) {
      edges {
        node {
          killChainPhases {
            kill_chain_name
          }
        }
      }
    }
  }
`;

interface SecurityCoverageAttackPatternsProps {
  securityCoverage: SecurityCoverageAttackPatternsFragment$data;
  dataKillChains: SecurityCoverageAttackPatternsKillChainPhasesFragment$key;
  relay: RelayRefetchProp;
}

const SecurityCoverageAttackPatternsComponent = ({
  securityCoverage,
  dataKillChains,
  relay,
}: SecurityCoverageAttackPatternsProps) => {
  const { t_i18n } = useFormatter();
  const [searchTerm, setSearchTerm] = useState('');
  const [viewMode, setViewMode] = useState<'matrix' | 'lines'>('matrix');
  const [selectedKillChain, setSelectedKillChain] = useState('mitre-attack');
  const [isModeOnlyActive, setIsModeOnlyActive] = useState(false);
  const theme = useTheme<Theme>();
  const killChainsData = useFragment(securityCoverageKillChainPhasesFragment, dataKillChains);
  const dedupedAttPatterns = useMemo(
    () => dedupeCoveredEntities(securityCoverage.attPatterns?.entities ?? []),
    [securityCoverage.attPatterns?.entities],
  );

  // Extract unique kill chains from all attack patterns
  const killChainsSet = new Set<string>();
  if (killChainsData.allAttackPatterns?.edges) {
    killChainsData.allAttackPatterns.edges.forEach((edge) => {
      if (edge?.node?.killChainPhases) {
        edge.node.killChainPhases.forEach((phase) => {
          if (phase?.kill_chain_name) {
            killChainsSet.add(phase.kill_chain_name);
          }
        });
      }
    });
  }
  const killChains = Array.from(killChainsSet).sort((a, b) => a.localeCompare(b));
  const showKillChainSelector = killChains.length > 1;

  const handleKillChainChange = (event: SelectChangeEvent<unknown>) => {
    setSelectedKillChain(event.target.value as string);
  };

  // Update selected kill chain if current one is not available
  useEffect(() => {
    if (killChains.length > 0 && !killChains.includes(selectedKillChain)) {
      setSelectedKillChain(killChains[0]);
    }
  }, [killChains.length, selectedKillChain]); // Use killChains.length instead of killChains to avoid dependency array issues

  return (
    <Card
      title={(
        <Stack direction="row" spacing={1} alignItems="center">
          <span>{t_i18n('Attack patterns coverage')}</span>
          <Tooltip title={t_i18n('Average coverage score from Security Coverage Result(s)')}>
            <InformationOutline fontSize="small" color="primary" />
          </Tooltip>
        </Stack>
      )}
      action={(
        <Stack direction="row" spacing={1}>
          <ToggleButtonGroup
            size="small"
            value={viewMode}
            exclusive
            onChange={(event, value) => value && setViewMode(value)}
            aria-label="view mode"
            style={{ height: 30 }}
            sx={{
              '& .MuiToggleButton-root': {
                padding: '5px 10px',
                '&.Mui-selected': {
                  backgroundColor: 'primary.main',
                  color: 'primary.contrastText',
                  '&:hover': {
                    backgroundColor: 'primary.dark',
                  },
                },
                '&:not(.Mui-selected)': {
                  backgroundColor: 'background.paper',
                  color: 'text.primary',
                },
              },
            }}
          >
            <ToggleButton value="matrix" aria-label="matrix view">
              <ViewModuleOutlined fontSize="small" />
            </ToggleButton>
            <ToggleButton value="lines" aria-label="lines view">
              <ViewListOutlined fontSize="small" />
            </ToggleButton>
          </ToggleButtonGroup>
          {showKillChainSelector && viewMode === 'matrix' && (
            <FormControl size="small" style={{ width: 194, height: 30 }}>
              <Select
                value={selectedKillChain}
                onChange={handleKillChainChange}
                variant="outlined"
                displayEmpty
                style={{ height: 30 }}
              >
                {killChains.map((chain) => (
                  <MenuItem key={chain} value={chain}>
                    {(() => {
                      if (chain === 'mitre-attack') return 'Mitre Attack';
                      if (chain === 'capec') return 'CAPEC';
                      if (chain === 'disarm') return 'Disarm';
                      return capitalizeFirstLetter(chain);
                    })()}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
          {viewMode === 'matrix' && (
            <Tooltip
              title={
                isModeOnlyActive
                  ? t_i18n('Display the whole matrix')
                  : t_i18n('Display only used techniques')
              }
            >
              <span>
                <IconButton
                  size="small"
                  color={isModeOnlyActive ? 'secondary' : 'primary'}
                  onClick={() => setIsModeOnlyActive((value) => !value)}
                >
                  <VisibilityOutlined fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
          )}
          <SearchInput
            variant="thin"
            onSubmit={setSearchTerm}
          />
        </Stack>
      )}
    >
      {(securityCoverage.attPatterns?.count ?? 0) > MAX_ATTACK_PATTERNS && (
        <Alert
          severity="warning"
          style={{ marginBottom: 10 }}
          content={t_i18n(
            'Showing {max} of {count} attack patterns. Some results are not displayed.',
            { values: { max: MAX_ATTACK_PATTERNS, count: securityCoverage.attPatterns?.count ?? 0 } },
          )}
        />
      )}
      {viewMode === 'matrix' ? (
        <SecurityCoverageAttackPatternsMatrix
          securityCoverage={securityCoverage}
          searchTerm={searchTerm}
          selectedKillChain={selectedKillChain}
          isModeOnlyActive={isModeOnlyActive}
        />
      ) : (
        <>
          <div className="clearfix" />
          <FieldOrEmpty source={securityCoverage.attPatterns?.entities || []}>
            <SecurityCoverageCoveredList
              entities={dedupedAttPatterns}
              style={{ marginTop: -10 }}
              rowRenderer={(attackPatternEntity) => {
                const attackPattern = attackPatternEntity.to;
                const coverage = attackPatternEntity.coverage_information || [];
                return (
                  <ListItem
                    key={attackPatternEntity.relationship_id}
                    dense={true}
                    divider={true}
                    disablePadding={true}
                    secondaryAction={(
                      <StixCoreRelationshipPopover
                        objectId={securityCoverage.id}
                        stixCoreRelationshipId={attackPatternEntity.relationship_id}
                        onDelete={() => relay.refetch({ id: securityCoverage.id })}
                        isCoverage={true}
                      />
                    )}
                  >
                    <ListItemButton
                      component={Link}
                      to={`/dashboard/analyses/security_coverages/${securityCoverage?.id}/relations/${attackPatternEntity.relationship_id}`}
                      style={{ width: '100%' }}
                    >
                      <ListItemIcon>
                        <ItemIcon color={theme.palette.primary.main} type="attack-pattern" />
                      </ListItemIcon>
                      <ListItemText
                        primary={(
                          <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                            <Typography variant="body2" component="span" noWrap sx={{ flex: '1 1 10%' }}>{attackPattern?.name}</Typography>
                            <Box sx={{ flex: '1 1 auto', display: 'flex', justifyContent: 'center' }}>
                              <SecurityCoverageScores
                                coverage_information={coverage}
                                variant="header"
                              />
                            </Box>
                          </Box>
                        )}
                      />
                    </ListItemButton>
                  </ListItem>
                );
              }}
            />
          </FieldOrEmpty>
        </>
      )}
    </Card>
  );
};

const SecurityCoverageAttackPatterns = createRefetchContainer(
  SecurityCoverageAttackPatternsComponent,
  {
    securityCoverage: graphql`
      fragment SecurityCoverageAttackPatternsFragment on SecurityCoverage {
        id
        attPatterns: coveredAttackPatterns(
          orderBy: created_at
          orderMode: asc
          first: 5000
        ) {
          count
          entities {
            relationship_id
            coverage_information {
              coverage_name
              coverage_score
            }
            to {
              id
              parent_types
              name
              description
            }
          }
        }
        ...SecurityCoverageAttackPatternsMatrix_securityCoverage
      }
    `,
  },
  graphql`
    query SecurityCoverageAttackPatternsRefetchQuery($id: String!) {
      securityCoverage(id: $id) {
        ...SecurityCoverageAttackPatternsFragment
      }
    }
  `,
);

export default SecurityCoverageAttackPatterns;
