import React, {Suspense, useState} from "react";
import Loader, {LoaderVariant} from "../../../../components/Loader";
import {graphql} from "react-relay";
import DataTable from "../../../../components/dataGrid/DataTable";
import useQueryLoading from "../../../../utils/hooks/useQueryLoading";
import {
  SecurityCoverageResultLinesPaginationQuery, SecurityCoverageResultLinesPaginationQuery$variables
} from "@components/analyses/security_coverages/__generated__/SecurityCoverageResultLinesPaginationQuery.graphql";
import {usePaginationLocalStorage} from "../../../../utils/hooks/useLocalStorage";
import {emptyFilterGroup} from "../../../../utils/filters/filtersUtils";
import {
  SecurityCoverageResultLines_data$data
} from "@components/analyses/security_coverages/__generated__/SecurityCoverageResultLines_data.graphql";
import {UsePreloadedPaginationFragment} from "../../../../utils/hooks/usePreloadedPaginationFragment";
import {DataTableProps} from "../../../../components/dataGrid/dataTableTypes";
import ItemMarkings from "../../../../components/ItemMarkings";
import {getMainRepresentative} from "../../../../utils/defaultRepresentatives";
import ItemEntityType from "../../../../components/ItemEntityType";
import StixCoreObjectLabels from "@components/common/stix_core_objects/StixCoreObjectLabels";
import ItemIcon from "../../../../components/ItemIcon";
import SecurityCoverageInformation from "@components/analyses/security_coverages/SecurityCoverageInformation";
import Tooltip from "@mui/material/Tooltip";
import {useFormatter} from "../../../../components/i18n";
import IconButton from "@common/button/IconButton";
import {InfoOutlined} from "@mui/icons-material";

interface SecurityCoverageResultProps {
  data: { id: string };
}

interface SecurityCoverageResultComponentProps {
  data: { id: string };
}

const securityCoverageResultLineFragment = graphql`
    fragment SecurityCoverageResultLine_node on StixCoreRelationship {
        id
        standard_id
        entity_type
        relationship_type
        to {
            ... on StixCoreObject {
                id
                draftVersion {
                    draft_id
                    draft_operation
                }
                standard_id
                entity_type
                created_at
                objectLabel {
                    id
                    value
                    color
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
                containersNumber {
                    total
                }
            }
            ... on AttackPattern {
                name
                x_mitre_id
            }
            ... on Campaign {
                name
            }
            ... on CourseOfAction {
                name
            }
            ... on ObservedData {
                name
            }
            ... on Report {
                name
            }
            ... on Grouping {
                name
            }
            ... on Note {
                attribute_abstract
                content
            }
            ... on Opinion {
                opinion
            }
            ... on Individual {
                name
            }
            ... on Organization {
                name
            }
            ... on Sector {
                name
            }
            ... on System {
                name
            }
            ... on Indicator {
                name
            }
            ... on Infrastructure {
                name
            }
            ... on IntrusionSet {
                name
            }
            ... on Position {
                name
            }
            ... on City {
                name
            }
            ... on AdministrativeArea {
                name
            }
            ... on Country {
                name
            }
            ... on Region {
                name
            }
            ... on Malware {
                name
            }
            ... on MalwareAnalysis {
                result_name
            }
            ... on ThreatActor {
                name
            }
            ... on Tool {
                name
            }
            ... on Vulnerability {
                name
            }
            ... on Incident {
                name
            }
            ... on Event {
                name
            }
            ... on Channel {
                name
            }
            ... on Narrative {
                name
            }
            ... on Language {
                name
            }
            ... on DataComponent {
                name
            }
            ... on DataSource {
                name
            }
            ... on Case {
                name
            }
            ... on Task {
                name
            }
            ...on Artifact {
                observable_value
            }
            ... on Indicator {
                name
            }
        }
        coverage_information{
            coverage_name
            coverage_score
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
    orderBy: { type: "StixCoreRelationshipsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "SecurityCoverageResultLinesRefetchQuery") {
      securityCoverage(id: $id) {
          id
          entity_type
          stixCoreRelationships(
              search: $search
              first: $count
              after: $cursor
              orderBy: $orderBy
              orderMode: $orderMode
              filters: $filters
          ) @connection(key: "PaginationSecurityCoverageResultLines__stixCoreRelationships") {
              edges {
                  node {
                      id
                      ...SecurityCoverageResultLine_node
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
        $orderBy: StixCoreRelationshipsOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...SecurityCoverageResultLines_data
            @arguments(
                id: $id
                search: $search
                count: $count
                cursor: $cursor
                orderBy: $orderBy
                orderMode: $orderMode
                filters: $filters
            )
    }
`;

const SecurityCoverageResultComponent = ({ data }: SecurityCoverageResultComponentProps) => {
  const { t_i18n } = useFormatter();
  const [tableRootRef, setTableRootRef] = useState<HTMLDivElement | null>(null);
  const LOCAL_STORAGE_KEY = `container-${data.id}-security-coverage-result`;
  const initialValues = {
    filters: { ...emptyFilterGroup },
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
    revoked: false,
  };

  const {
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<SecurityCoverageResultLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      id: data.id,
      ...initialValues,
    },
  );

  const queryPaginationOptions = {
    ...paginationOptions,
  } as unknown as SecurityCoverageResultLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<SecurityCoverageResultLinesPaginationQuery>(
    securityCoverageResultLinesQuery,
    queryPaginationOptions,
  );

  const withDisabledStyle = (coverage_information: { coverage_name: string; coverage_score: number | string }[], content: React.ReactNode) => (
    <span style={{ display: 'flex', opacity: coverage_information?.length ? 1 : 0.5 }}>
      {content}
    </span>
  );

  const contextFilters = {
    mode: 'and',
    filters: [
      {
        key: 'fromOrToId',
        values: [data.id],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: [],
  };

  const dataColumns: DataTableProps['dataColumns'] = {
    entity_type: {
      label: 'Type',
      percentWidth: 15,
      isSortable: true,
      render: ({ to, coverage_information }) => withDisabledStyle(coverage_information, (
        <>
          <ItemIcon type={to?.entity_type} />
          <ItemEntityType entityType={to?.entity_type} />
        </>
      )),
    },
    toName: {
      label: 'Name',
      percentWidth: 30,
      isSortable: false,
      render: ({ to, coverage_information }) => withDisabledStyle(coverage_information, (to?.x_mitre_id ? `[${to?.x_mitre_id}] ${to?.name}` : getMainRepresentative(to))),
    },
    coverage: {
      label: 'Coverage',
      percentWidth: 15,
      isSortable: false,
      render: ({ coverage_information } ) => withDisabledStyle(coverage_information, (
          coverage_information?.length ?
            (
              <SecurityCoverageInformation
                coverage_information={coverage_information}
                variant="header"
              />
            ) : (
              <Tooltip title={t_i18n('No executable test are available yet for this entity')}>
                <span>-</span>
              </Tooltip>
            )
        )
      ),
    },
    objectLabel: {
      label: 'Labels',
      percentWidth: 20,
      isSortable: false,
      render: ({ to, coverage_information }) => withDisabledStyle(coverage_information, (
          <StixCoreObjectLabels
            variant="inList"
            labels={to?.objectLabel}
          />
        )
      ),
    },
    objectMarking: {
      label: 'Marking',
      percentWidth: 20,
      isSortable: false,
      render: ({ to, coverage_information }) => withDisabledStyle(coverage_information, (
          <ItemMarkings
            markingDefinitions={to?.objectMarking ?? []}
            limit={1}
          />
        )
      ),
    },
  };

  return (
    <div data-testid="security-coverage-result-page" style={{ height: '70vh' }} ref={setTableRootRef}>
      {queryRef && (
        <DataTable
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          lineFragment={securityCoverageResultLineFragment}
          preloadedPaginationProps={{
            linesQuery: securityCoverageResultLinesQuery,
            linesFragment: securityCoverageResultLinesFragment,
            queryRef,
            nodePath: ['securityCoverage', 'stixCoreRelationships', 'pageInfo', 'globalCount'],
            setNumberOfElements: storageHelpers.handleSetNumberOfElements,
          } as UsePreloadedPaginationFragment<SecurityCoverageResultLinesPaginationQuery>}
          entityTypes={['stix-core-relationship']}
          availableFilterKeys={[ 'toTypes' ]}
          resolvePath={(data: SecurityCoverageResultLines_data$data) => data.securityCoverage?.stixCoreRelationships?.edges?.map((n) => n?.node)}
          dataColumns={dataColumns}
          exportContext={{ entity_id: data.id, entity_type: 'stix-core-relationship' }}
          contextFilters={contextFilters}
          rootRef={tableRootRef ?? undefined}
          additionalHeaderButtons={[
            <Tooltip
              key="security-coverage-result-global-information-tooltip"
              title={t_i18n('The Coverage Result Metric shows how much a specific entity was involved in the execution of the AEV scenario.\n Coverage may be partial if some injects were not executed, if placeholders were not resolved, or if the platform does not support certain actions')}
            >
              <IconButton color="primary" style={{ height: '100%' }}>
                <InfoOutlined />
              </IconButton>
            </Tooltip>,
          ]}
        />
      )}
    </div>
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