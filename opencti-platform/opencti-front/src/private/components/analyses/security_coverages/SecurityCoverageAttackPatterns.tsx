import Typography from '@mui/material/Typography';
import StixCoreRelationshipCreationFromEntity from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import { ViewListOutlined, ViewModuleOutlined } from '@mui/icons-material';
import FormControl from '@mui/material/FormControl';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import Paper from '@mui/material/Paper';
import React, { useEffect, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { SecurityCoverageAttackPatternsKillChainPhasesFragment$key } from './__generated__/SecurityCoverageAttackPatternsKillChainPhasesFragment.graphql';
import { SecurityCoverageAttackPatternsFragment$key } from './__generated__/SecurityCoverageAttackPatternsFragment.graphql';
import SecurityCoverageAttackPatternsMatrix from './SecurityCoverageAttackPatternsMatrix';
import SecurityCoverageAttackPatternsLines from './SecurityCoverageAttackPatternsLines';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';

const securityCoverageAttackPatternsFragment = graphql`
  fragment SecurityCoverageAttackPatternsFragment on SecurityCoverage {
    id
    ...SecurityCoverageAttackPatternsMatrix_securityCoverage
    ...SecurityCoverageAttackPatternsLines_securityCoverage
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
            targetEntities={[]}
            allowedRelationshipTypes={['has-covered']}
            targetStixDomainObjectTypes={['Attack-Pattern']}
            paginationOptions={{
              count: 25,
              orderBy: 'created_at',
              orderMode: 'asc',
              filters: {
                mode: 'and',
                filters: [],
                filterGroups: [],
              },
            }}
            paddingRight={220}
            onCreate={() => {
            }}
            isCoverage={true}
            openExports={false}
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
          <SecurityCoverageAttackPatternsLines
            securityCoverage={securityCoverage}
          />
        )}
      </Paper>
    </div>
  );
};

export default SecurityCoverageAttackPatterns;
