import React, {Suspense, useEffect} from "react";
import Loader, {LoaderVariant} from "../../../../components/Loader";
import {graphql, PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader} from "react-relay";
import {usePaginationLocalStorage} from "../../../../utils/hooks/useLocalStorage";
import {
  ContainerStixDomainObjectsLinesQuery$variables
} from "@components/common/containers/__generated__/ContainerStixDomainObjectsLinesQuery.graphql";
import {emptyFilterGroup, useGetDefaultFilterObject} from "../../../../utils/filters/filtersUtils";
import ListLines from "../../../../components/list_lines/ListLines";
import {FilterGroup} from "../../../../utils/filters/filtersHelpers-types";
import useAuth from "../../../../utils/hooks/useAuth";
import {
  SecurityCoverageResult_securityCoverage$key
} from "@components/analyses/security_coverages/__generated__/SecurityCoverageResult_securityCoverage.graphql";
import {
  SecurityCoverageResultReportQuery
} from "@components/analyses/security_coverages/__generated__/SecurityCoverageResultReportQuery.graphql";
import DataTable from "../../../../components/dataGrid/DataTable";
import ContainerStixCoreObjectPopover from "@components/common/containers/ContainerStixCoreObjectPopover";
import {UsePreloadedPaginationFragment} from "../../../../utils/hooks/usePreloadedPaginationFragment";
import {
  SecurityCoverageResultLines_data$data
} from "@components/analyses/security_coverages/__generated__/SecurityCoverageResultLines_data.graphql";
import {
  SecurityCoverageResultLinesPaginationQuery
} from "@components/analyses/security_coverages/__generated__/SecurityCoverageResultLinesPaginationQuery.graphql";
import useQueryLoading from "../../../../utils/hooks/useQueryLoading";
import {
  ContainerStixCyberObservablesLinesPaginationQuery
} from "@components/common/containers/__generated__/ContainerStixCyberObservablesLinesPaginationQuery.graphql";
import {containerStixCyberObservablesLinesQuery} from "@components/common/containers/ContainerStixCyberObservables";

interface SecurityCoverageResultProps {
  data: SecurityCoverageResult_securityCoverage$key;
}

interface SecurityCoverageResultComponentProps {
  data: SecurityCoverageResult_securityCoverage$key;
}

const securityCoverageResultLineFragment = graphql`
    fragment SecurityCoverageResultLine_node on StixCyberObservable {
        id
        entity_type
        observable_value
        created_at
        containersNumber {
            total
            count
        }
        createdBy {
            ... on Identity {
                id
                name
                entity_type
            }
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
        creators {
            id
            name
        }
    }
`;

const securityCoverageResultReportQuery = graphql`
  query SecurityCoverageResultReportQuery($id: String!) {
    report(id: $id) {
      id
      standard_id
      entity_type
      objects {
        edges {
          node {
            ... on BasicObject {
              id
              standard_id
              entity_type
            }
            ... on Artifact {
              observable_value
              objectLabel { id value color }
              objectMarking { id }
            }
            ... on Indicator {
              name
              objectLabel { id value color }
              objectMarking { id }
            }
            ... on AttackPattern {
              name
              x_mitre_id
              objectLabel { id value color }
              objectMarking { id }
            }
            ... on Vulnerability {
              name
              objectLabel { id value color }
              objectMarking { id }
            }
          }
        }
      }
    }
  }
`;

const securityCoverageResultFragment = graphql`
  fragment SecurityCoverageResult_securityCoverage on SecurityCoverage {
    id
    objectCovered {
      ... on Report {
        id
      }
    }
  }
`;

export const securityCoverageResultLinesFragment = graphql`
  fragment SecurityCoverageResultLines_data on Query
  @argumentDefinitions(
    id: { type: "String!" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    types: { type: "[String]" }
    orderBy: { type: "StixObjectOrStixRelationshipsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "SecurityCoverageResultLinesRefetchQuery") {
    container(id: $id) {
      id
      objects(
        types: $types
        search: $search
        first: $count
        after: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      ) @connection(key: "Pagination_objects") {
        edges {
          types
          node {
            ... on StixCyberObservable {
              id
              observable_value
              ...SecurityCoverageResultLine_node
            }
          }
        }
        pageInfo {
          endCursor
          hasNextPage
          globalCount
        }
      }
    }
  }
`;

export const securityCoverageResultLinesQuery = graphql`
  query SecurityCoverageResultLinesPaginationQuery(
    $id: String!
    $search: String
    $count: Int
    $cursor: ID
    $types: [String]
    $orderBy: StixObjectOrStixRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SecurityCoverageResultLines_data
      @arguments(
        id: $id
        search: $search
        types: $types
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

const SecurityCoverageResultComponent = ({ data }: SecurityCoverageResultComponentProps) => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const securityCoverage = useFragment(
    securityCoverageResultFragment,
    data,
  );

  console.log('securityCoverage', securityCoverage);

  // const reportData = usePreloadedQuery<SecurityCoverageResultReportQuery>(
  //   securityCoverageResultReportQuery,
  //   queryRef,
  // );
  // const reportObjects = (reportData.report?.objects?.edges ?? [])
  //   .map(edge =>
  //       edge?.node ? {
  //         name: edge.node.name ?? edge.node.observable_value,
  //         ...edge.node
  //       } : null
  //   )
  //   .filter(node => node);
  // console.log('reportObjects', reportObjects);

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const LOCAL_STORAGE_KEY = `container-${securityCoverage.id}-securityCoverageResult`;
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<ContainerStixDomainObjectsLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: emptyFilterGroup,
      searchTerm: '',
      sortBy: 'name',
      orderAsc: false,
      openExports: false,
    },
  );
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [],
    filterGroups: [],
  };
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
  } = viewStorage;
  const queryPaginationOptions = {
    ...paginationOptions,
    id: securityCoverage.id,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
    search: searchTerm,
    filters: contextFilters,
  } as unknown as ContainerStixDomainObjectsLinesQuery$variables;


  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['entity_type'], ['Stix-Cyber-Observable']),
    },
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
  };

  const queryRef = useQueryLoading<SecurityCoverageResultLinesPaginationQuery>(
    securityCoverageResultLinesQuery,
    queryPaginationOptions,
  );
  const preloadedPaginationProps = {
    linesQuery: securityCoverageResultLinesQuery,
    linesFragment: securityCoverageResultLineFragment,
    queryRef,
    nodePath: ['container', 'objects', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<SecurityCoverageResultLinesPaginationQuery>;

  const dataColumns = {
    entity_type: {
      label: 'Type',
      width: '12%',
      isSortable: true,
    },
    name: {
      label: 'Name',
      width: '28%',
      isSortable: true,
    },
    objectLabel: {
      label: 'Labels',
      width: '19%',
      isSortable: false,
    },
    objectMarking: {
      label: 'Marking',
      width: '9%',
      isSortable: isRuntimeSort,
    },
  };

  return (
    // <ListLines
    //   helpers={storageHelpers}
    //   sortBy={sortBy}
    //   orderAsc={orderAsc}
    //   dataColumns={dataColumns}
    //   handleSort={storageHelpers.handleSort}
    //   handleSearch={storageHelpers.handleSearch}
    //   handleAddFilter={storageHelpers.handleAddFilter}
    //   handleRemoveFilter={storageHelpers.handleRemoveFilter}
    //   handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
    //   handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
    //   handleToggleExports={storageHelpers.handleToggleExports}
    //   openExports={openExports}
    //   iconExtension={true}
    //   // exportContext={{ entity_id: containerData.id, entity_type: 'Stix-Domain-Object' }}
    //   filters={filters}
    //   keyword={searchTerm}
    //   secondaryAction={true}
    //   numberOfElements={numberOfElements}
    //   paginationOptions={queryPaginationOptions}
    //   // availableEntityTypes={['Stix-Domain-Object']}
    // >
    //
    // </ListLines>

    <>
      {queryRef && (
        <DataTable
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          lineFragment={securityCoverageResultLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          resolvePath={(data: SecurityCoverageResultLines_data$data) => data.container?.objects?.edges?.map((n) => n?.node)}
          dataColumns={dataColumns}
          contextFilters={contextFilters}
          exportContext={{ entity_id: securityCoverage.id, entity_type: 'Stix-Cyber-Observable' }}
          availableEntityTypes={['Stix-Cyber-Observable']}
          searchContextFinal={{ entityTypes: ['Stix-Cyber-Observable'] }}
          actions={(row) => {
            return (
              <div>
                <ContainerStixCoreObjectPopover
                  containerId={securityCoverage.id}
                  toId={row.id}
                  relationshipType="object"
                  paginationKey="Pagination_objects"
                  paginationOptions={queryPaginationOptions}
                />
              </div>
            );
          }}
        />
      )}
    </>
  );
}

const SecurityCoverageResult = ({ data }: SecurityCoverageResultProps) => {
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <SecurityCoverageResultComponent data={data} />
    </Suspense>
  );
};

export default SecurityCoverageResult;