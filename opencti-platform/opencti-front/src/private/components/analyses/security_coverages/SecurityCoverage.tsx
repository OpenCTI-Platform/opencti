import React, { Suspense, useEffect, useMemo, useState, useTransition } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader, useSubscription } from 'react-relay';
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
import { attackPatternsMatrixQuery } from '../../techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import { AttackPatternsMatrixQuery } from '../../techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import SecurityCoverageTestedEntitiesChart from './SecurityCoverageTestedEntitiesChart';
import SecurityCoverageMainInfo from './SecurityCoverageMainInfo';
import SecurityCoverageResultSelector from './SecurityCoverageResultSelector';
import { SecurityCoverageScopedQuery } from './__generated__/SecurityCoverageScopedQuery.graphql';
import { SecurityCoverageScopedSubscription } from './__generated__/SecurityCoverageScopedSubscription.graphql';
import { buildResultOptions, buildResultScopeVariables, resolveSelectedResult } from './securityCoverageResultScope';

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

// Same widgets and arguments as the scoped query: Relay stores the pushed data under the same keys,
// so the widgets of the selected result update on the events the coverage subscription already receives.
const securityCoverageScopedSubscription = graphql`
  subscription SecurityCoverageScopedSubscription($id: ID!, $filters: FilterGroup, $fromId: [String!]) {
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
    }
    ...SecurityCoverageMainInfo_securityCoverage
    ...SecurityCoverageTestedEntitiesChart_securityCoverage
    ...SecurityCoverageDetails_securityCoverage
    ...SecurityCoverageAttackPatternsFragment
  }
`;

type ScopedWidgetsData = SecurityCoverage_securityCoverage$data | NonNullable<SecurityCoverageScopedQuery['response']['securityCoverage']>;

interface SecurityCoverageScopedWidgetProps {
  securityCoverage: SecurityCoverage_securityCoverage$data;
  scopedQueryRef?: PreloadedQuery<SecurityCoverageScopedQuery> | null;
  children: (widgets: ScopedWidgetsData) => React.ReactNode;
}

interface SecurityCoverageScopedReaderProps {
  securityCoverage: SecurityCoverage_securityCoverage$data;
  scopedQueryRef: PreloadedQuery<SecurityCoverageScopedQuery>;
  children: (widgets: ScopedWidgetsData) => React.ReactNode;
}

// Separate component: usePreloadedQuery cannot be called conditionally and suspends while the query loads.
const SecurityCoverageScopedReader = ({
  securityCoverage,
  scopedQueryRef,
  children,
}: SecurityCoverageScopedReaderProps) => {
  const data = usePreloadedQuery(securityCoverageScopedQuery, scopedQueryRef);
  return <>{children(data.securityCoverage ?? securityCoverage)}</>;
};

// Gives a list widget the data of the selected result (scoped query), or the coverage data when there is no query ref.
// Only the widgets inside change source: the panels around never move in the React tree.
const SecurityCoverageScopedWidget = ({
  securityCoverage,
  scopedQueryRef,
  children,
}: SecurityCoverageScopedWidgetProps) => {
  if (!scopedQueryRef) return <>{children(securityCoverage)}</>;
  return (
    <SecurityCoverageScopedReader securityCoverage={securityCoverage} scopedQueryRef={scopedQueryRef}>
      {children}
    </SecurityCoverageScopedReader>
  );
};

interface SecurityCoverageScopedSubscriberProps {
  securityCoverageId: string;
  securityCoverageResultId: string;
}

// Mounted only while a result is displayed: "All results" needs no extra subscription.
const SecurityCoverageScopedSubscriber = ({
  securityCoverageId,
  securityCoverageResultId,
}: SecurityCoverageScopedSubscriberProps) => {
  const subscriptionConfig = useMemo(() => ({
    subscription: securityCoverageScopedSubscription,
    variables: buildResultScopeVariables(securityCoverageId, securityCoverageResultId),
  }), [securityCoverageId, securityCoverageResultId]);
  useSubscription<SecurityCoverageScopedSubscription>(subscriptionConfig);
  return null;
};

interface SecurityCoverageComponentProps {
  data: SecurityCoverage_securityCoverage$key;
  killChainsQueryRef: PreloadedQuery<SecurityCoverageKillChainsQuery>;
  matrixQueryRef: PreloadedQuery<AttackPatternsMatrixQuery>;
}

const SecurityCoverageComponent = ({
  data,
  killChainsQueryRef,
  matrixQueryRef,
}: SecurityCoverageComponentProps) => {
  const securityCoverage = useFragment(securityCoverageFragment, data);
  const dataKillChains = usePreloadedQuery(securityCoverageKillChainsQuery, killChainsQueryRef);
  const [selectedResultId, setSelectedResultId] = useState<string | null>(null);
  const [scopedQueryRef, loadScopedQuery, disposeScopedQuery] = useQueryLoader<SecurityCoverageScopedQuery>(securityCoverageScopedQuery);
  const [isPending, startTransition] = useTransition();

  const securityCoverageResults = securityCoverage.results ?? [];
  const isSelectedResultGone = selectedResultId !== null
    && resolveSelectedResult(securityCoverageResults, selectedResultId) === null;

  // What the content shows follows the query that is committed, not the menu: the menu answers at once,
  // the main info and the widgets switch together when the data of the new selection has arrived.
  const displayedResultId = selectedResultId && !isSelectedResultGone && scopedQueryRef
    ? scopedQueryRef.variables.fromId?.[0] ?? null
    : null;
  const displayedQueryRef = displayedResultId ? scopedQueryRef : null;

  const handleSelectionChange = (securityCoverageResultId: string | null) => {
    setSelectedResultId(securityCoverageResultId);
    // "All results" is no filter: the scoped query is never loaded without an id.
    if (securityCoverageResultId) {
      startTransition(() => {
        loadScopedQuery(
          buildResultScopeVariables(securityCoverage.id, securityCoverageResultId),
          { fetchPolicy: 'store-and-network' },
        );
      });
    } else {
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

  const widgetSx = { opacity: isPending ? 0.6 : 1, pointerEvents: isPending ? 'none' : 'auto' };
  return (
    <>
      {displayedResultId && (
        <SecurityCoverageScopedSubscriber securityCoverageId={securityCoverage.id} securityCoverageResultId={displayedResultId} />
      )}
      <Stack direction="row" sx={{ justifyContent: 'flex-end', marginBottom: 2 }}>
        <SecurityCoverageResultSelector
          options={buildResultOptions(securityCoverageResults)}
          value={selectedResultId}
          onChange={handleSelectionChange}
        />
      </Stack>
      <Grid container={true} spacing={3}>
        <Grid size={6} sx={widgetSx}>
          <SecurityCoverageMainInfo securityCoverage={securityCoverage} selectedResultId={displayedResultId} />
        </Grid>
        <Grid size={6} sx={widgetSx}>
          <SecurityCoverageScopedWidget securityCoverage={securityCoverage} scopedQueryRef={displayedQueryRef}>
            {(widgets) => <SecurityCoverageTestedEntitiesChart securityCoverage={widgets} isResultScoped={displayedResultId !== null} />}
          </SecurityCoverageScopedWidget>
        </Grid>

        <Grid size={6} sx={widgetSx}>
          <SecurityCoverageScopedWidget securityCoverage={securityCoverage} scopedQueryRef={displayedQueryRef}>
            {(widgets) => <SecurityCoverageDetails securityCoverage={widgets} isResultScoped={displayedResultId !== null} />}
          </SecurityCoverageScopedWidget>
        </Grid>

        <Grid size={6}>
          <StixDomainObjectOverview stixDomainObject={securityCoverage} />
        </Grid>

        <Grid size={12} sx={widgetSx}>
          <SecurityCoverageScopedWidget securityCoverage={securityCoverage} scopedQueryRef={displayedQueryRef}>
            {(widgets) => (
              <SecurityCoverageAttackPatterns
                securityCoverage={widgets}
                dataKillChains={dataKillChains}
                isResultScoped={displayedResultId !== null}
                matrixQueryRef={matrixQueryRef}
              />
            )}
          </SecurityCoverageScopedWidget>
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
    </>
  );
};

interface SecurityCoverageProps {
  data: SecurityCoverage_securityCoverage$key;
}

const SecurityCoverage = ({ data }: SecurityCoverageProps) => {
  const killChainsQueryRef = useQueryLoading<SecurityCoverageKillChainsQuery>(securityCoverageKillChainsQuery);
  // Loaded here, not in the widget: the widget remounts when the overview switches between all results and one result.
  const matrixQueryRef = useQueryLoading<AttackPatternsMatrixQuery>(attackPatternsMatrixQuery);

  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      {killChainsQueryRef && matrixQueryRef && (
        <SecurityCoverageComponent
          data={data}
          killChainsQueryRef={killChainsQueryRef}
          matrixQueryRef={matrixQueryRef}
        />
      )}
    </Suspense>
  );
};

export default SecurityCoverage;
