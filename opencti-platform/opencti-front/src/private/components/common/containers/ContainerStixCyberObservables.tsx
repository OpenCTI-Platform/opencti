import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixCyberObservablesLines, { containerStixCyberObservablesLinesQuery } from './ContainerStixCyberObservablesLines';
import StixCyberObservablesRightBar from '../../observations/stix_cyber_observables/StixCyberObservablesRightBar';
import ToolBar from '../../data/ToolBar';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { ModuleHelper } from '../../../../utils/platformModulesHelper';
import { ContainerStixCyberObservablesLinesQuery, ContainerStixCyberObservablesLinesQuery$variables } from './__generated__/ContainerStixCyberObservablesLinesQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { ContainerStixCyberObservables_container$data } from './__generated__/ContainerStixCyberObservables_container.graphql';
import useCopy from '../../../../utils/hooks/useCopy';
import { ContainerStixCyberObservablesLinesSearchQuery$data } from './__generated__/ContainerStixCyberObservablesLinesSearchQuery.graphql';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import { ContainerStixCyberObservableLineDummy } from './ContainerStixCyberObservableLine';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import { ContainerStixCyberObservableLine_node$data } from './__generated__/ContainerStixCyberObservableLine_node.graphql';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ContainerAddStixCoreObjectsInLine from './ContainerAddStixCoreObjectsInLine';

export const ContainerStixCyberObservablesLinesSearchQuery = graphql`
  query ContainerStixCyberObservablesLinesSearchQuery(
    $id: String!
    $types: [String]
    $search: String
    $filters: FilterGroup
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
  enableReferences?: boolean;
}

const ContainerStixCyberObservablesComponent: FunctionComponent<
ContainerStixCyberObservablesComponentProps
> = ({ container, enableReferences }) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const LOCAL_STORAGE_KEY = `container-${container.id}-stixCyberObservables`;
  const {
    viewStorage,
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage<ContainerStixCyberObservablesLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      id: container.id,
      filters: emptyFilterGroup,
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
    handleSwitchGlobalMode,
    handleSwitchLocalMode,
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
  const handleClear = () => {
    handleAddProperty('types', []);
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

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Stix-Cyber-Observable']);
  const contextFilters = {
    mode: 'and',
    filters: [
      {
        key: 'objects',
        values: [container.id],
        operator: 'eq',
        mode: 'or',
      },
      {
        key: 'entity_type',
        values: types && types.length > 0 ? types : ['Stix-Cyber-Observable'],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ContainerStixCyberObservablesLinesQuery$variables;

  const handleCopy = useCopy<ContainerStixCyberObservablesLinesSearchQuery$data>(
    {
      filters: contextFilters,
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
        label: 'Platform creation date',
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
    queryPaginationOptions,
  );
  return (
    <div data-testid="container-observables-pages">
      <UserContext.Consumer>
        {({ platformModuleHelpers }) => (
          <ExportContextProvider>
            <ListLines
              helpers={helpers}
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={buildColumns(platformModuleHelpers)}
              handleSort={handleSort}
              handleSearch={handleSearch}
              secondaryAction={true}
              numberOfElements={numberOfElements}
              handleAddFilter={handleAddFilter}
              handleRemoveFilter={handleRemoveFilter}
              handleSwitchGlobalMode={handleSwitchGlobalMode}
              handleSwitchLocalMode={handleSwitchLocalMode}
              handleToggleSelectAll={handleToggleSelectAll}
              selectAll={selectAll}
              iconExtension={true}
              handleToggleExports={handleToggleExports}
              exportContext={{ entity_type: 'Stix-Cyber-Observable' }}
              keyword={searchTerm}
              openExports={openExports}
              filters={filters}
              paginationOptions={queryPaginationOptions}
              availableEntityTypes={['Stix-Cyber-Observable']}
              createButton={FABReplaced && <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <ContainerAddStixCoreObjectsInLine
                  containerId={container.id}
                  targetStixCoreObjectTypes={['Stix-Cyber-Observable']}
                  containerStixCoreObjects={[...(container.objects?.edges ?? [])]}
                  paginationOptions={queryPaginationOptions}
                  enableReferences={enableReferences}
                />
              </Security>}
            >
              {queryRef && (
                <React.Suspense
                  fallback={
                    <>
                      {Array(20)
                        .fill(0)
                        .map((_, idx) => (
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
                    paginationOptions={queryPaginationOptions}
                    dataColumns={buildColumns(platformModuleHelpers)}
                    onTypesChange={handleToggle}
                    openExports={openExports}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    onToggleEntity={onToggleEntity}
                    selectAll={selectAll}
                    setNumberOfElements={handleSetNumberOfElements}
                    setSelectedElements={setSelectedElements}
                    enableReferences={enableReferences}
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
              filters={contextFilters}
              handleClearSelectedElements={handleClearSelectedElements}
              variant="large"
              container={container}
              handleCopy={handleCopy}
              warning={true}
              warningMessage={t_i18n('Be careful, you are about to delete the selected observables (not the relationships)')}
            />
            <StixCyberObservablesRightBar
              types={types}
              handleToggle={handleToggle}
              handleClear={handleClear}
              openExports={openExports}
            />
          </ExportContextProvider>
        )}
      </UserContext.Consumer>
    </div>
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
        objects {
          edges {
            types
            node {
              ... on BasicObject {
                id
              }
            }
          }
        }
      }
    `,
  },
);

export default ContainerStixCyberObservables;
