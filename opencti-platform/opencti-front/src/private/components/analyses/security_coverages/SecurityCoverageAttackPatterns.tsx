import Typography from '@mui/material/Typography';
import StixCoreRelationshipCreationFromEntity, { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import { ViewListOutlined, ViewModuleOutlined } from '@mui/icons-material';
import FormControl from '@mui/material/FormControl';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import Paper from '@mui/material/Paper';
import React, { useEffect, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import StixCoreRelationshipPopover from '@components/common/stix_core_relationships/StixCoreRelationshipPopover';
import { Box, ListItemButton } from '@mui/material';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import SecurityCoverageInformation from '@components/analyses/security_coverages/SecurityCoverageInformation';
import { useTheme } from '@mui/styles';
import { SecurityCoverageAttackPatternsKillChainPhasesFragment$key } from './__generated__/SecurityCoverageAttackPatternsKillChainPhasesFragment.graphql';
import { SecurityCoverageAttackPatternsFragment$key } from './__generated__/SecurityCoverageAttackPatternsFragment.graphql';
import SecurityCoverageAttackPatternsMatrix from './SecurityCoverageAttackPatternsMatrix';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';

const securityCoverageAttackPatternsFragment = graphql`
  fragment SecurityCoverageAttackPatternsFragment on SecurityCoverage {
    id
    attPatterns: stixCoreRelationships(
        orderBy: created_at
        orderMode: asc
        relationship_type: "has-covered"
        toTypes: ["Attack-Pattern"]
        first: 25
    ) @connection(key: "Pagination_attPatterns") {
        edges {
            node {
                id
                coverage_information {
                    coverage_name
                    coverage_score
                }
                to {
                    ... on AttackPattern {
                        id
                        parent_types
                        name
                        description
                    }
                }
            }
        }
    }
    ...SecurityCoverageAttackPatternsMatrix_securityCoverage
  }
`;

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
  data: SecurityCoverageAttackPatternsFragment$key
  dataKillChains: SecurityCoverageAttackPatternsKillChainPhasesFragment$key
}

const SecurityCoverageAttackPatterns = ({
  data,
  dataKillChains,
}: SecurityCoverageAttackPatternsProps) => {
  const { t_i18n } = useFormatter();
  const [searchTerm, setSearchTerm] = useState('');
  const [viewMode, setViewMode] = useState<'matrix' | 'lines'>('matrix');
  const [selectedKillChain, setSelectedKillChain] = useState('mitre-attack');
  const theme = useTheme<Theme>();
  const paginationOptions = {
    orderBy: 'created_at',
    orderMode: 'asc',
    relationship_type: 'has-covered',
    toTypes: ['Attack-Pattern'],
  };
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);
  const handleOnCreate = () => {
    setTargetEntities([]);
  };
  const securityCoverage = useFragment(securityCoverageAttackPatternsFragment, data);
  const killChainsData = useFragment(securityCoverageKillChainPhasesFragment, dataKillChains);

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
    <div style={{ marginTop: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 15, justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <Typography variant="h4" style={{ whiteSpace: 'nowrap', marginRight: 10 }}>
            {t_i18n('Attack patterns coverage')}
          </Typography>
          <StixCoreRelationshipCreationFromEntity
            entityId={securityCoverage.id}
            objectId={securityCoverage.id}
            connectionKey={'Pagination_attPatterns'}
            targetEntities={targetEntities}
            currentView={'relationships'}
            allowedRelationshipTypes={['has-covered']}
            targetStixDomainObjectTypes={['Attack-Pattern']}
            paginationOptions={paginationOptions}
            paddingRight={220}
            onCreate={handleOnCreate}
            isCoverage={true}
            variant="inLine"
          />
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
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
              <ViewModuleOutlined fontSize="small"/>
            </ToggleButton>
            <ToggleButton value="lines" aria-label="lines view">
              <ViewListOutlined fontSize="small"/>
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
                      if (chain === 'mitre-attack') return 'MITRE ATT&CK';
                      if (chain === 'capec') return 'CAPEC';
                      if (chain === 'disarm') return 'DISARM';
                      return chain.toUpperCase();
                    })()}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
          <SearchInput
            variant="thin"
            onSubmit={setSearchTerm}
          />
        </div>
      </div>
      <Paper
        variant="outlined"
        style={{
          padding: 15,
          borderRadius: 4,
        }}
        className="paper-for-grid"
      >
        {viewMode === 'matrix' ? (
          <SecurityCoverageAttackPatternsMatrix
            securityCoverage={securityCoverage}
            searchTerm={searchTerm}
            selectedKillChain={selectedKillChain}
          />
        ) : (
          <>
            <div className="clearfix" />
            <List style={{ marginTop: -10 }}>
              <FieldOrEmpty source={securityCoverage.attPatterns?.edges || []}>
                {(securityCoverage.attPatterns?.edges || []).map((attackPatternEdge) => {
                  const attackPattern = attackPatternEdge.node.to;
                  const coverage = attackPatternEdge.node.coverage_information || [];
                  return (
                    <ListItem
                      key={attackPatternEdge.node.id}
                      dense={true}
                      divider={true}
                      disablePadding={true}
                      secondaryAction={
                        <StixCoreRelationshipPopover
                          objectId={securityCoverage.id}
                          connectionKey={'Pagination_attPatterns'}
                          stixCoreRelationshipId={attackPatternEdge.node.id}
                          paginationOptions={paginationOptions}
                          isCoverage={true}
                        />
                                  }
                    >
                      <ListItemButton
                        component={Link}
                        to={`/dashboard/analyses/security_coverages/${securityCoverage?.id}/relations/${attackPatternEdge.node.id}`}
                        style={{ width: '100%' }}
                      >
                        <ListItemIcon>
                          <ItemIcon color={theme.palette.primary.main} type="attack-pattern" />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                              <Typography variant="body2" component="span" sx={{ flex: '1 1 10%' }}>{attackPattern?.name}</Typography>
                              <Box sx={{ flex: '1 1 auto', display: 'flex', justifyContent: 'center' }}>
                                <SecurityCoverageInformation
                                  coverage_information={coverage}
                                  variant="header"
                                />
                              </Box>
                            </Box>
                                          }
                        />
                      </ListItemButton>
                    </ListItem>
                  );
                })}
              </FieldOrEmpty>
            </List>
          </>
        )}
      </Paper>
    </div>
  );
};

export default SecurityCoverageAttackPatterns;
