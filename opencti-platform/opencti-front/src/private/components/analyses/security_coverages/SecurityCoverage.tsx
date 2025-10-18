import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import SecurityCoverageDetails from './SecurityCoverageDetails';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../notes/StixCoreObjectOrStixCoreRelationshipNotes';
import SecurityCoverageAttackPatternsMatrix from './SecurityCoverageAttackPatternsMatrix';
import { SecurityCoverage_securityCoverage$key } from './__generated__/SecurityCoverage_securityCoverage.graphql';
import { useFormatter } from '../../../../components/i18n';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

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
  const [searchTerm] = useState('');
  const [selectedKillChain] = useState('mitre-attack');

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
      <Grid item xs={12}>
        <Typography variant="h4" gutterBottom={true}>
          {t_i18n('Attack patterns coverage')}
        </Typography>
        <Paper 
          variant="outlined" 
          style={{ 
            marginTop: 10, 
            padding: 15, 
            borderRadius: 4 
          }} 
          className="paper-for-grid"
        >
          <SecurityCoverageAttackPatternsMatrix
            securityCoverage={securityCoverage}
            searchTerm={searchTerm}
            selectedKillChain={selectedKillChain}
          />
        </Paper>
      </Grid>
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
