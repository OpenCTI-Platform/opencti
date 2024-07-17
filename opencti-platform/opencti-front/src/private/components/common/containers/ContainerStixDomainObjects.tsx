import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { ContainerStixDomainObjectLine_node$data } from '@components/common/containers/__generated__/ContainerStixDomainObjectLine_node.graphql';
import {
  ContainerStixDomainObjectsLinesQuery,
  ContainerStixDomainObjectsLinesQuery$variables,
} from '@components/common/containers/__generated__/ContainerStixDomainObjectsLinesQuery.graphql';
import { ContainerStixDomainObjectLineDummy } from '@components/common/containers/ContainerStixDomainObjectLine';
import { ContainerStixDomainObjects_container$key } from '@components/common/containers/__generated__/ContainerStixDomainObjects_container.graphql';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixDomainObjectsLines, { containerStixDomainObjectsLinesQuery } from './ContainerStixDomainObjectsLines';
import StixDomainObjectsRightBar from '../stix_domain_objects/StixDomainObjectsRightBar';
import ToolBar from '../../data/ToolBar';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useAuth from '../../../../utils/hooks/useAuth';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../../components/i18n';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useHelper from '../../../../utils/hooks/useHelper';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ContainerAddStixCoreObjectsInLine from './ContainerAddStixCoreObjectsInLine';

const ContainerStixDomainObjectsFragment = graphql`
    fragment ContainerStixDomainObjects_container on Container {
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
              ...ContainerStixDomainObjectLine_node
            }
          }
        }
    }
`;

const ContainerStixDomainObjects = ({
  container, enableReferences,
}: {
  container: ContainerStixDomainObjects_container$key;
  enableReferences?: boolean
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const containerData = useFragment(
    ContainerStixDomainObjectsFragment,
    container,
  );
  const LOCAL_STORAGE_KEY = `container-${containerData.id}-stixDomainObjects`;
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
      types: [],
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

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Stix-Domain-Object']);
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'objects', values: [containerData.id], operator: 'eq' },
      {
        key: 'entity_type',
        values: (types && types.length > 0) ? types : ['Stix-Domain-Object'],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const queryPaginationOptions = {
    ...paginationOptions,
    id: containerData.id,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
    search: searchTerm,
    filters: contextFilters,
  } as unknown as ContainerStixDomainObjectsLinesQuery$variables;
  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
    numberOfSelectedElements,
  } = useEntityToggle<ContainerStixDomainObjectLine_node$data>(LOCAL_STORAGE_KEY);
  const queryRef = useQueryLoading<ContainerStixDomainObjectsLinesQuery>(
    containerStixDomainObjectsLinesQuery,
    queryPaginationOptions,
  );
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
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
  const currentSelection = containerData.objects?.edges ?? [];
  const selectWithoutInferred = currentSelection.filter((edge) => (edge?.types ?? ['manual']).includes('manual'));
  return (
    <ListLines
      helpers={storageHelpers}
      sortBy={sortBy}
      orderAsc={orderAsc}
      dataColumns={dataColumns}
      handleSort={storageHelpers.handleSort}
      handleSearch={storageHelpers.handleSearch}
      handleAddFilter={storageHelpers.handleAddFilter}
      handleRemoveFilter={storageHelpers.handleRemoveFilter}
      handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
      handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
      handleToggleExports={storageHelpers.handleToggleExports}
      openExports={openExports}
      handleToggleSelectAll={handleToggleSelectAll}
      selectAll={selectAll}
      iconExtension={true}
      exportContext={{ entity_id: containerData.id, entity_type: 'Stix-Domain-Object' }}
      filters={filters}
      keyword={searchTerm}
      secondaryAction={true}
      numberOfElements={numberOfElements}
      paginationOptions={queryPaginationOptions}
      availableEntityTypes={['Stix-Domain-Object']}
      createButton={FABReplaced && <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ContainerAddStixCoreObjectsInLine
          containerId={containerData.id}
          targetStixCoreObjectTypes={['Stix-Domain-Object']}
          paginationOptions={queryPaginationOptions}
          containerStixCoreObjects={selectWithoutInferred}
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
                  <ContainerStixDomainObjectLineDummy
                    key={idx}
                    dataColumns={dataColumns}
                  />
                ))}
            </>
          }
        >
          <ContainerStixDomainObjectsLines
            queryRef={queryRef}
            paginationOptions={queryPaginationOptions}
            dataColumns={dataColumns}
            setNumberOfElements={storageHelpers.handleSetNumberOfElements}
            onTypesChange={storageHelpers.handleToggleTypes}
            openExports={openExports}
            selectedElements={selectedElements}
            deSelectedElements={deSelectedElements}
            onToggleEntity={onToggleEntity}
            selectAll={selectAll}
            enableReferences={enableReferences}
          />
          <ToolBar
            selectedElements={selectedElements}
            deSelectedElements={deSelectedElements}
            numberOfSelectedElements={numberOfSelectedElements}
            selectAll={selectAll}
            filters={contextFilters}
            search={searchTerm}
            handleClearSelectedElements={handleClearSelectedElements}
            variant="large"
            container={containerData}
            warning={true}
            warningMessage={t_i18n('Be careful, you are about to delete the selected entities (not the relationships)')}
          />
          <StixDomainObjectsRightBar
            types={types}
            handleToggle={storageHelpers.handleToggleTypes}
            handleClear={storageHelpers.handleClearTypes}
            openExports={openExports}
          />
        </React.Suspense>
      )}
    </ListLines>
  );
};

export default ContainerStixDomainObjects;
