import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Grid from '@mui/material/Grid2';
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
import SecurityCoverageTestedEntitiesChart from './SecurityCoverageTestedEntitiesChart';
import SecurityCoverageMainInfo from './SecurityCoverageMainInfo';

const securityCoverageKillChainsQuery = graphql`
  query SecurityCoverageKillChainsQuery {
    ...SecurityCoverageAttackPatternsKillChainPhasesFragment
  }
`;

const securityCoverageFragment = graphql`
  fragment SecurityCoverage_securityCoverage on SecurityCoverage {
    id
    standard_id
    external_uri
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
    ...SecurityCoverageMainInfo_securityCoverage
    ...SecurityCoverageTestedEntitiesChart_securityCoverage
    ...SecurityCoverageDetails_securityCoverage
    ...SecurityCoverageAttackPatternsFragment
  }
`;

interface SecurityCoverageComponentProps {
  data: SecurityCoverage_securityCoverage$key;
  killChainsQueryRef: PreloadedQuery<SecurityCoverageKillChainsQuery>;
}

const SecurityCoverageComponent = ({
  data,
  killChainsQueryRef,
}: SecurityCoverageComponentProps) => {
  const securityCoverage = useFragment(securityCoverageFragment, data);
  const dataKillChains = usePreloadedQuery(securityCoverageKillChainsQuery, killChainsQueryRef);
  return (
    <Grid container={true} spacing={3}>
      <Grid size={6}>
        <SecurityCoverageMainInfo securityCoverage={securityCoverage} />
      </Grid>
      <Grid size={6}>
        <SecurityCoverageTestedEntitiesChart securityCoverage={securityCoverage} />
      </Grid>

      <Grid size={6}>
        <SecurityCoverageDetails securityCoverage={securityCoverage} />
      </Grid>

      <Grid size={6}>
        <StixDomainObjectOverview stixDomainObject={securityCoverage} />
      </Grid>

      <Grid size={12}>
        <SecurityCoverageAttackPatterns
          data={securityCoverage}
          dataKillChains={dataKillChains}
        />
      </Grid>

      <Grid size={6}>
        <StixCoreObjectExternalReferences stixCoreObjectId={securityCoverage.id} />
      </Grid>

      <Grid size={6}>
        <StixCoreObjectLatestHistory stixCoreObjectId={securityCoverage.id} />
      </Grid>

      <Grid size={12}>
        <StixCoreObjectOrStixCoreRelationshipNotes stixCoreObjectOrStixCoreRelationshipId={securityCoverage.id} />
      </Grid>
    </Grid>
  );
};

interface SecurityCoverageProps {
  data: SecurityCoverage_securityCoverage$key;
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
