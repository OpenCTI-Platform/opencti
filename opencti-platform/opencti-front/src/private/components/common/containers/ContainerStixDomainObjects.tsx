import React from 'react';
import * as R from 'ramda';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import {
  ContainerStixDomainObjectLine_node$data,
} from '@components/common/containers/__generated__/ContainerStixDomainObjectLine_node.graphql';
import {
  ContainerStixDomainObjectsLinesQuery, ContainerStixDomainObjectsLinesQuery$variables,
} from '@components/common/containers/__generated__/ContainerStixDomainObjectsLinesQuery.graphql';
import { ContainerStixDomainObjectLineDummy } from '@components/common/containers/ContainerStixDomainObjectLine';
import {
  ContainerStixDomainObjects_container$key,
} from '@components/common/containers/__generated__/ContainerStixDomainObjects_container.graphql';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixDomainObjectsLines, {
  containerStixDomainObjectsLinesQuery,
} from './ContainerStixDomainObjectsLines';
import StixDomainObjectsRightBar from '../stix_domain_objects/StixDomainObjectsRightBar';
import { convertFilters } from '../../../../utils/ListParameters';
import { defaultValue } from '../../../../utils/Graph';
import ToolBar from '../../data/ToolBar';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../../components/list_lines';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useAuth from '../../../../utils/hooks/useAuth';

const useStyles = makeStyles(() => ({
  container: {
    margin: '20px 0 0 0',
    padding: '0 260px 90px 0',
  },
}));

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
            }
  `;

const ContainerStixDomainObjects = ({ container }: { container: ContainerStixDomainObjects_container$key }) => {
  const classes = useStyles();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const containerData = useFragment(ContainerStixDomainObjectsFragment, container);
  const LOCAL_STORAGE_KEY = `view-container-${containerData.id}-stixDomainObjects`;
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<ContainerStixDomainObjectsLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: {} as Filters,
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

  const finalPaginationOptions = {
    ...paginationOptions,
    id: containerData.id,
    types: (types && types.length > 0) ? types : ['Stix-Domain-Object'],
  };
  const exportFilters = {
    objectContains: [{ id: containerData.id, value: defaultValue(containerData) }],
    entity_type:
      (types && types.length > 0) ? R.map((n) => ({ id: n, value: n }), types) : [],
    ...filters,
  };
  const exportFinalFilters = convertFilters(exportFilters);
  const exportPaginationOptions = {
    filters: exportFinalFilters,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
    search: searchTerm,
  };
  const backgroundTaskFilters = {
    objectContains: [{ id: containerData.id, value: defaultValue(containerData) }],
    entity_type:
      (types && types.length > 0)
        ? R.map((n) => ({ id: n, value: n }), types)
        : [{ id: 'Stix-Domain-Object', value: 'Stix-Domain-Object' }],
    ...filters,
  };

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
    finalPaginationOptions,
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

  return (
      <div className={classes.container}>
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={storageHelpers.handleSearch}
          handleAddFilter={storageHelpers.handleAddFilter}
          handleRemoveFilter={storageHelpers.handleRemoveFilter}
          handleToggleExports={storageHelpers.handleToggleExports}
          openExports={openExports}
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          iconExtension={true}
          exportEntityType="Stix-Domain-Object"
          exportContext={`of-container-${containerData.id}`}
          filters={filters}
          availableFilterKeys={[
            'labelledBy',
            'markedBy',
            'created_at_start_date',
            'created_at_end_date',
            'createdBy',
          ]}
          keyword={searchTerm}
          secondaryAction={true}
          numberOfElements={numberOfElements}
          paginationOptions={exportPaginationOptions}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((idx) => (
                      <ContainerStixDomainObjectLineDummy key={idx} dataColumns={dataColumns}/>
                    ))}
                </>
              }
            >
              <ContainerStixDomainObjectsLines
                queryRef={queryRef}
                paginationOptions={finalPaginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                onTypesChange={storageHelpers.handleToggleTypes}
                openExports={openExports}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
              />
              <ToolBar
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                numberOfSelectedElements={numberOfSelectedElements}
                selectAll={selectAll}
                filters={backgroundTaskFilters}
                search={searchTerm}
                handleClearSelectedElements={handleClearSelectedElements}
                variant="large"
                container={containerData}
                warning={true}
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
      </div>
  );
};

export default ContainerStixDomainObjects;
