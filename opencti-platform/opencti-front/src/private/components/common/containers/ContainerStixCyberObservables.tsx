import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixCyberObservablesLines, {
  containerStixCyberObservablesLinesQuery,
} from './ContainerStixCyberObservablesLines';
import StixCyberObservablesRightBar from '../../observations/stix_cyber_observables/StixCyberObservablesRightBar';
import ToolBar from '../../data/ToolBar';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { Theme } from '../../../../components/Theme';
import { Filters } from '../../../../components/list_lines';
import { ModuleHelper } from '../../../../utils/platformModulesHelper';
import {
  ContainerStixCyberObservablesLinesQuery,
  ContainerStixCyberObservablesLinesQuery$variables,
  StixObjectOrStixRelationshipsFiltering,
} from './__generated__/ContainerStixCyberObservablesLinesQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { ContainerStixCyberObservables_container$data } from './__generated__/ContainerStixCyberObservables_container.graphql';
import useCopy from '../../../../utils/hooks/useCopy';
import { ContainerStixCyberObservablesLinesSearchQuery$data } from './__generated__/ContainerStixCyberObservablesLinesSearchQuery.graphql';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import { convertFilters } from '../../../../utils/ListParameters';
import { defaultValue } from '../../../../utils/Graph';
import { ContainerStixCyberObservableLineDummy } from './ContainerStixCyberObservableLine';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import { ContainerStixCyberObservableLine_node$data } from './__generated__/ContainerStixCyberObservableLine_node.graphql';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: '20px 0 0 0',
    padding: '0 260px 90px 0',
  },
}));

export const ContainerStixCyberObservablesLinesSearchQuery = graphql`
  query ContainerStixCyberObservablesLinesSearchQuery(
    $id: String!
    $types: [String]
    $search: String
    $filters: [StixObjectOrStixRelationshipsFiltering]
    $count: Int
  ) {
    container(id: $id) {
      id
      objects(
        types: $types
        search: $search
        first: $count
        filters: $filters
      ) {
        edges {
          types
          node {
            ... on StixCyberObservable {
              id
              observable_value
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

interface ContainerStixCyberObservablesComponentProps {
  container: ContainerStixCyberObservables_container$data;
}

const ContainerStixCyberObservablesComponent: FunctionComponent<
ContainerStixCyberObservablesComponentProps
> = ({ container }) => {
  const classes = useStyles();
  const LOCAL_STORAGE_KEY = `view-container-${container.id}-stixCyberObservables`;
  const {
    viewStorage,
    paginationOptions: rawPaginationOptions,
    helpers,
  } = usePaginationLocalStorage<ContainerStixCyberObservablesLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      id: container.id,
      filters: {} as Filters,
      searchTerm: '',
      sortBy: 'created_at',
      orderAsc: false,
      openExports: false,
      types: [] as string[],
    },
  );
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
    types,
  } = viewStorage;
  const {
    handleRemoveFilter,
    handleSearch,
    handleSort,
    handleToggleExports,
    handleAddFilter,
    handleSetNumberOfElements,
    handleAddProperty,
  } = helpers;
  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    setSelectedElements,
    onToggleEntity,
    numberOfSelectedElements,
  } = useEntityToggle<ContainerStixCyberObservableLine_node$data>(
    LOCAL_STORAGE_KEY,
  );
  // Format filters Front (object)
  const toolbarFilters = {
    objectContains: [{ id: container.id, value: defaultValue(container) }],
    entity_type:
      types && types.length > 0
        ? types.map((n) => ({ id: n, value: n }))
        : [{ id: 'Stix-Cyber-Observable', value: 'Stix-Cyber-Observable' }],
    ...filters,
  };
  // Format filters query (options + filters)
  const paginationOptions = {
    ...rawPaginationOptions,
    types: types && types.length > 0 ? types : ['Stix-Cyber-Observable'],
    filters: convertFilters(
      filters,
    ) as unknown as StixObjectOrStixRelationshipsFiltering[],
  };
  const exportPaginationOptions = {
    ...rawPaginationOptions,
    types: types && types.length > 0 ? types : ['Stix-Cyber-Observable'],
    filters: convertFilters(
      toolbarFilters,
    ) as unknown as StixObjectOrStixRelationshipsFiltering[],
  };
  const handleToggle = (type: string) => {
    if (types?.includes(type)) {
      handleAddProperty(
        'types',
        types.filter((x) => x !== type),
      );
    } else {
      handleAddProperty('types', types ? [...types, type] : [type]);
    }
  };
  const getValuesForCopy = (
    data: ContainerStixCyberObservablesLinesSearchQuery$data,
  ) => {
    return (data.container?.objects?.edges ?? [])
      .map((o) => ({ id: o?.node.id, value: o?.node.observable_value }))
      .filter((o) => o.id) as { id: string; value: string }[];
  };
  const handleCopy = useCopy<ContainerStixCyberObservablesLinesSearchQuery$data>(
    {
      filters: toolbarFilters,
      searchTerm: searchTerm ?? '',
      query: ContainerStixCyberObservablesLinesSearchQuery,
      selectedValues: Object.values(selectedElements).map(
        ({ observable_value }) => observable_value,
      ),
      deselectedIds: Object.values(deSelectedElements).map((o) => o.id),
      elementId: container.id,
      getValuesForCopy,
    },
    selectAll,
  );
  const handleClear = () => {
    handleAddProperty('types', []);
  };
  const buildColumns = (platformModuleHelpers: ModuleHelper | undefined) => {
    const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable() ?? false;
    return {
      entity_type: {
        label: 'Type',
        width: '12%',
        isSortable: true,
      },
      observable_value: {
        label: 'Value',
        width: '28%',
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '19%',
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      created_at: {
        label: 'Creation date',
        width: '10%',
        isSortable: true,
      },
      analyses: {
        label: 'Analyses',
        width: '8%',
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        width: '9%',
        isSortable: isRuntimeSort,
      },
    };
  };
  const queryRef = useQueryLoading<ContainerStixCyberObservablesLinesQuery>(
    containerStixCyberObservablesLinesQuery,
    paginationOptions,
  );
  return (
    <UserContext.Consumer>
      {({ platformModuleHelpers }) => (
        <ExportContextProvider>
          <div className={classes.container}>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={buildColumns(platformModuleHelpers)}
              handleSort={handleSort}
              handleSearch={handleSearch}
              secondaryAction={true}
              numberOfElements={numberOfElements}
              handleAddFilter={handleAddFilter}
              handleRemoveFilter={handleRemoveFilter}
              handleToggleSelectAll={handleToggleSelectAll}
              selectAll={selectAll}
              iconExtension={true}
              handleToggleExports={handleToggleExports}
              exportEntityType="Stix-Cyber-Observable"
              keyword={searchTerm}
              openExports={openExports}
              exportContext={`of-container-${container.id}`}
              filters={filters}
              availableFilterKeys={[
                'labelledBy',
                'markedBy',
                'created_at_start_date',
                'created_at_end_date',
                'x_opencti_score',
                'createdBy',
                'sightedBy',
              ]}
              paginationOptions={exportPaginationOptions}
            >
              {queryRef && (
                <React.Suspense
                  fallback={
                    <>
                      {Array(20)
                        .fill(0)
                        .map((idx) => (
                          <ContainerStixCyberObservableLineDummy
                            key={idx}
                            dataColumns={buildColumns(platformModuleHelpers)}
                          />
                        ))}
                    </>
                  }
                >
                  <ContainerStixCyberObservablesLines
                    queryRef={queryRef}
                    paginationOptions={paginationOptions}
                    dataColumns={buildColumns(platformModuleHelpers)}
                    onTypesChange={handleToggle}
                    openExports={openExports}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    onToggleEntity={onToggleEntity}
                    selectAll={selectAll}
                    setNumberOfElements={handleSetNumberOfElements}
                    setSelectedElements={setSelectedElements}
                  />
                </React.Suspense>
              )}
            </ListLines>
            <ToolBar
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              numberOfSelectedElements={numberOfSelectedElements}
              selectAll={selectAll}
              search={searchTerm}
              filters={toolbarFilters}
              handleClearSelectedElements={handleClearSelectedElements}
              variant="large"
              container={container}
              handleCopy={handleCopy}
              warning={true}
            />
            <StixCyberObservablesRightBar
              types={types}
              handleToggle={handleToggle}
              handleClear={handleClear}
              openExports={openExports}
            />
          </div>
        </ExportContextProvider>
      )}
    </UserContext.Consumer>
  );
};

const ContainerStixCyberObservables = createFragmentContainer(
  ContainerStixCyberObservablesComponent,
  {
    container: graphql`
      fragment ContainerStixCyberObservables_container on Container {
        id
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
        ... on ObservedData {
          name
          first_observed
          last_observed
        }
        ...ContainerHeader_container
      }
    `,
  },
);

export default ContainerStixCyberObservables;
