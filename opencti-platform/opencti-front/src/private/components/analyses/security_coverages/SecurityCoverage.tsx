import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import SearchInput from '../../../../components/SearchInput';
import SecurityCoverageDetails from './SecurityCoverageDetails';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../notes/StixCoreObjectOrStixCoreRelationshipNotes';
import SecurityCoverageAttackPatternsMatrix from './SecurityCoverageAttackPatternsMatrix';
import { SecurityCoverage_securityCoverage$key } from './__generated__/SecurityCoverage_securityCoverage.graphql';
import { SecurityCoverageKillChainsQuery } from './__generated__/SecurityCoverageKillChainsQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

const securityCoverageKillChainsQuery = graphql`
  query SecurityCoverageKillChainsQuery {
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

const securityCoverageFragment = graphql`
  fragment SecurityCoverage_securityCoverage on SecurityCoverage {
    id
    standard_id
    entity_type
    x_opencti_stix_ids
    spec_version
    revoked
    confidence
    created
    modified
    created_at
    updated_at
    createdBy {
      ... on Identity {
        id
        name
        entity_type
        x_opencti_reliability
      }
    }
    creators {
      id
      name
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    name
    description
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    objectCovered {
      ... on Report {
        id
        name
        entity_type
      }
      ... on Malware {
        id
        name
        entity_type
      }
    }
    coverage_last_result
    coverage_valid_from
    coverage_valid_to
    coverage_information {
      coverage_name
      coverage_score
    }
    ...SecurityCoverageDetails_securityCoverage
    ...SecurityCoverageAttackPatternsMatrix_securityCoverage
  }
`;

interface SecurityCoverageProps {
  data: SecurityCoverage_securityCoverage$key;
}

const SecurityCoverage: FunctionComponent<SecurityCoverageProps> = ({ data }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const securityCoverage = useFragment(securityCoverageFragment, data);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedKillChain, setSelectedKillChain] = useState('mitre-attack');

  // Fetch all available kill chains from attack patterns
  const killChainsData = useLazyLoadQuery<SecurityCoverageKillChainsQuery>(
    securityCoverageKillChainsQuery,
    {},
  );

  const handleKillChainChange = (event: SelectChangeEvent<unknown>) => {
    setSelectedKillChain(event.target.value as string);
  };

  const handleSearch = (value: string) => {
    setSearchTerm(value);
  };

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

  // Update selected kill chain if current one is not available
  useEffect(() => {
    if (killChains.length > 0 && !killChains.includes(selectedKillChain)) {
      setSelectedKillChain(killChains[0]);
    }
  }, [killChains.length, selectedKillChain]); // Use killChains.length instead of killChains to avoid dependency array issues

  const showKillChainSelector = killChains.length > 1;

  return (
    <>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item xs={6}>
          <SecurityCoverageDetails securityCoverage={securityCoverage} />
        </Grid>
        <Grid item xs={6}>
          <StixDomainObjectOverview stixDomainObject={securityCoverage} />
        </Grid>
      </Grid>
      <div style={{ marginTop: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 15 }}>
          <Typography variant="h4" style={{ flex: 1 }}>
            {t_i18n('Attack patterns coverage')}
          </Typography>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            {showKillChainSelector && (
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
              onSubmit={handleSearch}
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
          <SecurityCoverageAttackPatternsMatrix
            securityCoverage={securityCoverage}
            searchTerm={searchTerm}
            selectedKillChain={selectedKillChain}
          />
        </Paper>
      </div>
      <Grid
        container={true}
        spacing={3}
        style={{ marginTop: 10 }}
      >
        <Grid item xs={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={securityCoverage.id} />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={securityCoverage.id} />
        </Grid>
        <Grid item xs={12}>
          <StixCoreObjectOrStixCoreRelationshipNotes stixCoreObjectOrStixCoreRelationshipId={securityCoverage.id} />
        </Grid>
      </Grid>
    </>
  );
};

export default SecurityCoverage;
