import Typography from '@mui/material/Typography';
import StixCoreRelationshipCreationFromEntity, { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import { ViewListOutlined, ViewModuleOutlined } from '@mui/icons-material';
// fds:keep-mui the library Tooltip is a compound API; this call site converts with the wider Tooltip wave
import Tooltip from '@mui/material/Tooltip';
import { ButtonGroup, ButtonGroupItem, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import React, { useEffect, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import StixCoreRelationshipPopover from '@components/common/stix_core_relationships/StixCoreRelationshipPopover';
import { Box, ListItemButton, Stack } from '@mui/material';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import SecurityCoverageScores from '@components/analyses/security_coverages/SecurityCoverageScores';
import { useTheme } from '@mui/styles';
import { SecurityCoverageAttackPatternsKillChainPhasesFragment$key } from './__generated__/SecurityCoverageAttackPatternsKillChainPhasesFragment.graphql';
import { SecurityCoverageAttackPatternsFragment$key } from './__generated__/SecurityCoverageAttackPatternsFragment.graphql';
import SecurityCoverageAttackPatternsMatrix from './SecurityCoverageAttackPatternsMatrix';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { capitalizeFirstLetter } from '../../../../utils/String';
import Card from '../../../../components/common/card/Card';

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
  data: SecurityCoverageAttackPatternsFragment$key;
  dataKillChains: SecurityCoverageAttackPatternsKillChainPhasesFragment$key;
}

// The library item declares a 16x16 glyph.
const GLYPH = { fontSize: 16 };

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

  const handleKillChainChange = (value: string) => {
    setSelectedKillChain(value);
  };

  // Update selected kill chain if current one is not available
  useEffect(() => {
    if (killChains.length > 0 && !killChains.includes(selectedKillChain)) {
      setSelectedKillChain(killChains[0]);
    }
  }, [killChains.length, selectedKillChain]); // Use killChains.length instead of killChains to avoid dependency array issues

  return (
    <Card
      title={t_i18n('Attack patterns coverage')}
      action={(
        <Stack direction="row" spacing={1} alignItems="center">
          <StixCoreRelationshipCreationFromEntity
            entityId={securityCoverage.id}
            objectId={securityCoverage.id}
            connectionKey="Pagination_attPatterns"
            targetEntities={targetEntities}
            currentView="relationships"
            allowedRelationshipTypes={['has-covered']}
            targetStixDomainObjectTypes={['Attack-Pattern']}
            paginationOptions={paginationOptions}
            paddingRight={220}
            onCreate={handleOnCreate}
            isCoverage={true}
            variant="inLine"
          />
          <ButtonGroup
            size="sm"
            value={viewMode}
            onValueChange={(value) => value && setViewMode(value as 'matrix' | 'lines')}
            aria-label={t_i18n('Change view')}
          >
            <Tooltip title={t_i18n('Matrix view')}>
              <ButtonGroupItem
                value="matrix"
                aria-label="matrix view"
                icon={<ViewModuleOutlined sx={GLYPH} />}
              />
            </Tooltip>
            <Tooltip title={t_i18n('Lines view')}>
              <ButtonGroupItem
                value="lines"
                aria-label="lines view"
                icon={<ViewListOutlined sx={GLYPH} />}
              />
            </Tooltip>
          </ButtonGroup>
          <SearchInput
            variant="thin"
            onSubmit={setSearchTerm}
          />
        </Stack>
      )}
    >
      {viewMode === 'matrix' ? (
        <>
          {showKillChainSelector && (
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 1 }}>
              <Select
                value={selectedKillChain}
                onValueChange={handleKillChainChange}
              >
                <SelectTrigger aria-label={t_i18n('Kill chain')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent aria-label={t_i18n('Kill chain')}>
                  {killChains.map((chain) => (
                    <SelectItem key={chain} value={chain}>
                      {(() => {
                        if (chain === 'mitre-attack') return 'Mitre Attack';
                        if (chain === 'capec') return 'CAPEC';
                        if (chain === 'disarm') return 'Disarm';
                        return capitalizeFirstLetter(chain);
                      })()}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Box>
          )}
          <SecurityCoverageAttackPatternsMatrix
            securityCoverage={securityCoverage}
            searchTerm={searchTerm}
            selectedKillChain={selectedKillChain}
          />
        </>
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
                    secondaryAction={(
                      <StixCoreRelationshipPopover
                        objectId={securityCoverage.id}
                        connectionKey="Pagination_attPatterns"
                        stixCoreRelationshipId={attackPatternEdge.node.id}
                        paginationOptions={paginationOptions}
                        isCoverage={true}
                      />
                    )}
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
                        primary={(
                          <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                            <Typography variant="body2" component="span" sx={{ flex: '1 1 10%' }}>{attackPattern?.name}</Typography>
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
              })}
            </FieldOrEmpty>
          </List>
        </>
      )}
    </Card>
  );
};

export default SecurityCoverageAttackPatterns;
