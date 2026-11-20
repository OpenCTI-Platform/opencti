import React, { Suspense, useEffect, useRef, useState, useTransition } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import SecurityCoverageDetails from './SecurityCoverageDetails';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../notes/StixCoreObjectOrStixCoreRelationshipNotes';
import SecurityCoverageAttackPatterns from './SecurityCoverageAttackPatterns';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SecurityCoverage_securityCoverage$data, SecurityCoverage_securityCoverage$key } from './__generated__/SecurityCoverage_securityCoverage.graphql';
import { SecurityCoverageKillChainsQuery } from './__generated__/SecurityCoverageKillChainsQuery.graphql';
import { SecurityCoverageAttackPatternsKillChainPhasesFragment$key } from './__generated__/SecurityCoverageAttackPatternsKillChainPhasesFragment.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import SecurityCoverageTestedEntitiesChart from './SecurityCoverageTestedEntitiesChart';
import SecurityCoverageMainInfo from './SecurityCoverageMainInfo';
import SecurityCoverageResultSelector from './SecurityCoverageResultSelector';
import { SecurityCoverageScopedQuery } from './__generated__/SecurityCoverageScopedQuery.graphql';
import { buildResultOptions, buildResultScopeVariables, buildScopeRefreshKey, resolveSelectedResult } from './securityCoverageResultScope';

const securityCoverageKillChainsQuery = graphql`
  query SecurityCoverageKillChainsQuery {
    ...SecurityCoverageAttackPatternsKillChainPhasesFragment
  }
`;

// Widgets whose data depends on the selected security coverage result.
const securityCoverageScopedQuery = graphql`
  query SecurityCoverageScopedQuery($id: String!, $filters: FilterGroup, $fromId: [String!]) {
    securityCoverage(id: $id) {
      id
      ...SecurityCoverageTestedEntitiesChart_securityCoverage @arguments(fromId: $fromId)
      ...SecurityCoverageDetails_securityCoverage @arguments(vulnerabilityFilters: $filters)
      ...SecurityCoverageAttackPatternsFragment @arguments(filters: $filters)
    }
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
    ...WorkflowStatusStixDomainObject_data
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
    results {
      id
      name
      external_uri
      coverage_last_result
    }
    ...SecurityCoverageMainInfo_securityCoverage
    ...SecurityCoverageTestedEntitiesChart_securityCoverage
    ...SecurityCoverageDetails_securityCoverage
    ...SecurityCoverageAttackPatternsFragment
  }
`;

interface SecurityCoverageOverviewGridProps {
  // root data: main info, overview, external references, history and notes
  securityCoverage: SecurityCoverage_securityCoverage$data;
  // fragment references of the three list widgets: the coverage itself (all results) or the scoped query
  widgets: SecurityCoverage_securityCoverage$data | NonNullable<SecurityCoverageScopedQuery['response']['securityCoverage']>;
  selectedResultId: string | null;
  dataKillChains: SecurityCoverageAttackPatternsKillChainPhasesFragment$key;
  isPending: boolean;
}

const SecurityCoverageOverviewGrid = ({
  securityCoverage,
  widgets,
  selectedResultId,
  dataKillChains,
  isPending,
}: SecurityCoverageOverviewGridProps) => {
  const widgetSx = { opacity: isPending ? 0.6 : 1 };
  return (
    <Grid container={true} spacing={3}>
      <Grid size={6}>
        <SecurityCoverageMainInfo securityCoverage={securityCoverage} selectedResultId={selectedResultId} />
      </Grid>
      <Grid size={6} sx={widgetSx}>
        <SecurityCoverageTestedEntitiesChart securityCoverage={widgets} />
      </Grid>

      <Grid size={6} sx={widgetSx}>
        <SecurityCoverageDetails securityCoverage={widgets} />
      </Grid>

      <Grid size={6}>
        <StixDomainObjectOverview stixDomainObject={securityCoverage} />
      </Grid>

      <Grid size={12} sx={widgetSx}>
        <SecurityCoverageAttackPatterns
          securityCoverage={widgets}
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

interface SecurityCoverageScopedGridProps extends Omit<SecurityCoverageOverviewGridProps, 'widgets'> {
  scopedQueryRef: PreloadedQuery<SecurityCoverageScopedQuery>;
}

// Separate component: usePreloadedQuery cannot be called conditionally and suspends while the query loads.
const SecurityCoverageScopedGrid = ({
  scopedQueryRef,
  securityCoverage,
  ...gridProps
}: SecurityCoverageScopedGridProps) => {
  const data = usePreloadedQuery(securityCoverageScopedQuery, scopedQueryRef);
  return (
    <SecurityCoverageOverviewGrid
      securityCoverage={securityCoverage}
      widgets={data.securityCoverage ?? securityCoverage}
      {...gridProps}
    />
  );
};

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
  const [selectedResultId, setSelectedResultId] = useState<string | null>(null);
  const [scopedQueryRef, loadScopedQuery, disposeScopedQuery] = useQueryLoader<SecurityCoverageScopedQuery>(securityCoverageScopedQuery);
  const [isPending, startTransition] = useTransition();

  const securityCoverageResults = securityCoverage.results ?? [];
  const isSelectedResultGone = selectedResultId !== null
    && resolveSelectedResult(securityCoverageResults, selectedResultId) === null;
  const refreshKey = buildScopeRefreshKey(securityCoverage.updated_at, securityCoverageResults);
  const lastRefreshKey = useRef(refreshKey);

  const handleSelectionChange = (securityCoverageResultId: string | null) => {
    // "All results" is no filter: the scoped query is never loaded without an id.
    if (securityCoverageResultId) {
      // The selection moves with the query so that the menu, the main info and the widgets always agree.
      startTransition(() => {
        setSelectedResultId(securityCoverageResultId);
        loadScopedQuery(
          buildResultScopeVariables(securityCoverage.id, securityCoverageResultId),
          { fetchPolicy: 'store-and-network' },
        );
      });
    } else {
      setSelectedResultId(null);
      disposeScopedQuery();
    }
  };

  // The selected result has been removed (or is no longer visible): back to all results.
  useEffect(() => {
    if (isSelectedResultGone) {
      setSelectedResultId(null);
      disposeScopedQuery();
    }
  }, [isSelectedResultGone, disposeScopedQuery]);

  // The subscription pushed an update of the coverage or of one of its results: refetch the selected result.
  useEffect(() => {
    if (lastRefreshKey.current === refreshKey) return;
    lastRefreshKey.current = refreshKey;
    if (selectedResultId && !isSelectedResultGone) {
      startTransition(() => {
        loadScopedQuery(
          buildResultScopeVariables(securityCoverage.id, selectedResultId),
          { fetchPolicy: 'network-only' },
        );
      });
    }
  }, [refreshKey, selectedResultId, isSelectedResultGone, securityCoverage.id, loadScopedQuery]);

  const gridProps = { securityCoverage, selectedResultId, dataKillChains, isPending };
  return (
    <>
      <Stack direction="row" sx={{ justifyContent: 'flex-end', marginBottom: 2 }}>
        <SecurityCoverageResultSelector
          options={buildResultOptions(securityCoverageResults)}
          value={selectedResultId}
          onChange={handleSelectionChange}
        />
      </Stack>
      {selectedResultId && scopedQueryRef
        ? <SecurityCoverageScopedGrid scopedQueryRef={scopedQueryRef} {...gridProps} />
        : <SecurityCoverageOverviewGrid widgets={securityCoverage} {...gridProps} />}
    </>
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
