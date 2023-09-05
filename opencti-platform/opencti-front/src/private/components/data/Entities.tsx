import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import {
  EntitiesStixDomainObjectsLinesPaginationQuery,
  EntitiesStixDomainObjectsLinesPaginationQuery$variables,
} from '@components/data/entities/__generated__/EntitiesStixDomainObjectsLinesPaginationQuery.graphql';
import { EntitiesStixDomainObjectLineDummy } from '@components/data/entities/EntitiesStixDomainObjectLine';
import {
  EntitiesStixDomainObjectLine_node$data,
} from '@components/data/entities/__generated__/EntitiesStixDomainObjectLine_node.graphql';
import ListLines from '../../../components/list_lines/ListLines';
import ToolBar from './ToolBar';
import EntitiesStixDomainObjectsLines, {
  entitiesStixDomainObjectsLinesQuery,
} from './entities/EntitiesStixDomainObjectsLines';
import StixDomainObjectsRightBar from '../common/stix_domain_objects/StixDomainObjectsRightBar';
import useAuth from '../../../utils/hooks/useAuth';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../components/list_lines';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const useStyles = makeStyles(() => ({
  container: {
    paddingRight: 250,
  },
}));

const LOCAL_STORAGE_KEY = 'view-entities';

const Entities = () => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const classes = useStyles();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<EntitiesStixDomainObjectsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: {} as Filters,
      searchTerm: '',
      sortBy: 'created_at',
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
  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
    numberOfSelectedElements,
  } = useEntityToggle<EntitiesStixDomainObjectLine_node$data>(LOCAL_STORAGE_KEY);
  const queryRef = useQueryLoading<EntitiesStixDomainObjectsLinesPaginationQuery>(
    entitiesStixDomainObjectsLinesQuery,
    paginationOptions,
  );

  const renderLines = () => {
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;

    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '12%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '25%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      creator: {
        label: 'Creators',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '15%',
        isSortable: false,
      },
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
        width: '8%',
      },
    };

    const entityTypes = types?.map((n) => ({ id: n, value: n })) ?? [];
    const toolBarFilters = entityTypes.length > 0
      ? { ...filters, entity_type: entityTypes }
      : {
        ...filters,
        entity_type: [
          {
            id: 'Stix-Domain-Object',
            value: 'Stix-Domain-Object',
          },
        ],
      };
    return (
      <>
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
              exportEntityType="Stix-Domain-Object"
              selectAll={selectAll}
              disableCards={true}
              keyword={searchTerm}
              filters={filters}
              noPadding={true}
              paginationOptions={paginationOptions}
              numberOfElements={numberOfElements}
              iconExtension={true}
              secondaryAction={true}
              availableFilterKeys={[
                'labelledBy',
                'markedBy',
                'createdBy',
                'source_reliability',
                'confidence',
                'creator',
                'created_start_date',
                'created_end_date',
                'created_at_start_date',
                'created_at_end_date',
              ]}
            >
              {queryRef && (
                <React.Suspense
                  fallback={
                    <>
                      {Array(20)
                        .fill(0)
                        .map((idx) => (
                          <EntitiesStixDomainObjectLineDummy key={idx} dataColumns={dataColumns} />
                        ))}
                    </>
                  }
                >
                  <EntitiesStixDomainObjectsLines
                    queryRef={queryRef}
                    paginationOptions={paginationOptions}
                    dataColumns={dataColumns}
                    onLabelClick={storageHelpers.handleAddFilter}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    onToggleEntity={onToggleEntity}
                    selectAll={selectAll}
                    setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                  />
                  <ToolBar
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    numberOfSelectedElements={numberOfSelectedElements}
                    selectAll={selectAll}
                    search={searchTerm}
                    filters={toolBarFilters}
                    handleClearSelectedElements={handleClearSelectedElements}
                    variant="large"
                  />
                </React.Suspense>
              )}
          </ListLines>
      </>
    );
  };
  return (
      <ExportContextProvider>
        <div className={classes.container}>
          {renderLines()}
          <StixDomainObjectsRightBar
            types={types}
            handleToggle={storageHelpers.handleToggleTypes}
            handleClear={storageHelpers.handleClearTypes}
          />
        </div>
      </ExportContextProvider>
  );
};

export default Entities;
