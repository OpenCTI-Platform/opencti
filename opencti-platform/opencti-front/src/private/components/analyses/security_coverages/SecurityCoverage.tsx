import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import SecurityCoverageDetails from './SecurityCoverageDetails';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../notes/StixCoreObjectOrStixCoreRelationshipNotes';
import SecurityCoverageAttackPatterns from './SecurityCoverageAttackPatterns';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SecurityCoverage_securityCoverage$key } from './__generated__/SecurityCoverage_securityCoverage.graphql';
import { SecurityCoverageKillChainsQuery } from './__generated__/SecurityCoverageKillChainsQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

const securityCoverageKillChainsQuery = graphql`
  query SecurityCoverageKillChainsQuery {
    ...SecurityCoverageAttackPatternsKillChainPhasesFragment
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
    periodicity
    duration
    type_affinity
    platforms_affinity
    coverage_last_result
    coverage_valid_from
    coverage_valid_to
    coverage_information {
      coverage_name
      coverage_score
    }
    ...SecurityCoverageDetails_securityCoverage
    ...SecurityCoverageAttackPatternsFragment
  }
`;

interface SecurityCoverageComponentProps {
  data: SecurityCoverage_securityCoverage$key;
  killChainsQueryRef: PreloadedQuery<SecurityCoverageKillChainsQuery>
}

const SecurityCoverageComponent = ({
  data,
  killChainsQueryRef,
}: SecurityCoverageComponentProps) => {
  const classes = useStyles();
  const securityCoverage = useFragment(securityCoverageFragment, data);
  const dataKillChains = usePreloadedQuery(securityCoverageKillChainsQuery, killChainsQueryRef);

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
      <SecurityCoverageAttackPatterns
        data={securityCoverage}
        dataKillChains={dataKillChains}
      />
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

interface SecurityCoverageProps {
  data: SecurityCoverage_securityCoverage$key,
}

const SecurityCoverage = ({ data }: SecurityCoverageProps) => {
  const killChainsQueryRef = useQueryLoading<SecurityCoverageKillChainsQuery>(securityCoverageKillChainsQuery);

  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      {killChainsQueryRef && (
        <SecurityCoverageComponent
          data={data}
          killChainsQueryRef={killChainsQueryRef}
        />
      )}
    </Suspense>
  );
};

export default SecurityCoverage;
