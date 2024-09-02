import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { graphql } from 'react-relay';
import { ArtifactsLinesPaginationQuery, ArtifactsLinesPaginationQuery$variables } from '@components/observations/__generated__/ArtifactsLinesPaginationQuery.graphql';
import { ArtifactsLines_data$data } from '@components/observations/__generated__/ArtifactsLines_data.graphql';
import Tooltip from '@mui/material/Tooltip';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import ArtifactCreation from './artifacts/ArtifactCreation';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { truncate } from '../../../utils/String';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';

const LOCAL_STORAGE_KEY = 'artifacts';

const artifactLineFragment = graphql`
  fragment ArtifactsLine_node on Artifact {
    id
    entity_type
    parent_types
    observable_value
    created_at
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
    importFiles {
      edges {
        node {
          id
          name
          size
          metaData {
            mimetype
          }
        }
      }
    }
  }
`;

const artifactsLinesQuery = graphql`
  query ArtifactsLinesPaginationQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ArtifactsLines_data
    @arguments(
      types: $types
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const artifactsLinesFragment = graphql`
  fragment ArtifactsLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixCyberObservablesOrdering"
      defaultValue: created_at
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ArtifactsLinesRefetchQuery") {
    stixCyberObservables(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixCyberObservables") {
      edges {
        node {
          id
          entity_type
          observable_value
          created_at
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...ArtifactsLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

const Artifacts: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
    types: ['Artifact'],
  };
  const { viewStorage: { filters }, paginationOptions, helpers: storageHelpers } = usePaginationLocalStorage<ArtifactsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Artifact', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ArtifactsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<ArtifactsLinesPaginationQuery>(
    artifactsLinesQuery,
    queryPaginationOptions,
  );

  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const dataColumns: DataTableProps['dataColumns'] = {
    observable_value: { isSortable: isRuntimeSort },
    file_name: {
      label: 'File name',
      percentWidth: 15,
      isSortable: false,
      render: (data, { column: { size } }) => {
        const file = (data.importFiles?.edges && data.importFiles.edges.length > 0)
          ? data.importFiles.edges[0]?.node
          : { name: 'N/A', metaData: { mimetype: 'N/A' }, size: 0 };
        return (<Tooltip title={file?.name}><>{truncate(file?.name, size * 0.113)}</></Tooltip>);
      },
    },
    file_mime_type: {
      label: 'Mime/Type',
      percentWidth: 8,
      isSortable: false,
      render: (data, { column: { size } }) => {
        const file = (data.importFiles?.edges && data.importFiles.edges.length > 0)
          ? data.importFiles.edges[0]?.node
          : { name: 'N/A', metaData: { mimetype: 'N/A' }, size: 0 };
        return (<Tooltip title={file?.metaData?.mimetype}><>{truncate(file?.metaData?.mimetype, size * 0.113)}</></Tooltip>);
      },
    },
    file_size: {
      label: 'File size',
      percentWidth: 7,
      isSortable: false,
      render: (data, { b }) => {
        const file = (data.importFiles?.edges && data.importFiles.edges.length > 0)
          ? data.importFiles.edges[0]?.node
          : { name: 'N/A', metaData: { mimetype: 'N/A' }, size: 0 };
        return (<Tooltip title={file?.metaData?.mimetype}><>{b(file?.size)}</></Tooltip>);
      },
    },
    createdBy: { percentWidth: 10, isSortable: isRuntimeSort },
    creator: { percentWidth: 10, isSortable: isRuntimeSort },
    objectLabel: { percentWidth: 10 },
    created_at: { percentWidth: 10 },
    objectMarking: { percentWidth: 10, isSortable: isRuntimeSort },
  };

  const preloadedPaginationOptions = {
    linesQuery: artifactsLinesQuery,
    linesFragment: artifactsLinesFragment,
    queryRef,
    nodePath: ['stixCyberObservables', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ArtifactsLinesPaginationQuery>;

  return (
    <div data-testid="artifact-page">
      <ExportContextProvider>
        <Breadcrumbs variant="list" elements={[{ label: t_i18n('Observations') }, { label: t_i18n('Artifacts'), current: true }]} />
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: ArtifactsLines_data$data) => data.stixCyberObservables?.edges?.map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            toolbarFilters={contextFilters}
            lineFragment={artifactLineFragment}
            preloadedPaginationProps={preloadedPaginationOptions}
            exportContext={{ entity_type: 'Artifact' }}
            createButton={isFABReplaced && (
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <ArtifactCreation
                  paginationOptions={queryPaginationOptions}
                />
              </Security>
            )}
          />
        )}
        {!isFABReplaced && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <ArtifactCreation
              paginationOptions={queryPaginationOptions}
            />
          </Security>
        )}
      </ExportContextProvider>
    </div>
  );
};

export default Artifacts;
