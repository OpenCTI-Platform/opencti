import React from 'react';
import {
  RelationshipsStixCoreRelationshipsLinesPaginationQuery,
  RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables,
} from '@components/data/relationships/__generated__/RelationshipsStixCoreRelationshipsLinesPaginationQuery.graphql';
import { RelationshipsStixCoreRelationshipLine_node$data } from '@components/data/relationships/__generated__/RelationshipsStixCoreRelationshipLine_node.graphql';
import { RelationshipsStixCoreRelationshipLineDummy } from '@components/data/relationships/RelationshipsStixCoreRelationshipLine';
import ListLines from '../../../components/list_lines/ListLines';
import RelationshipsStixCoreRelationshipsLines, { relationshipsStixCoreRelationshipsLinesQuery } from './relationships/RelationshipsStixCoreRelationshipsLines';
import useAuth from '../../../utils/hooks/useAuth';
import ToolBar from './ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { buildEntityTypeBasedFilterContext, emptyFilterGroup, getDefaultFilterObjFromArray } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY = 'relationships';

const Relationships = () => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: {
        ...emptyFilterGroup,
        filters: getDefaultFilterObjFromArray(['fromId', 'toId']),
      },
      searchTerm: '',
      sortBy: 'created_at',
      orderAsc: false,
      openExports: false,
    },
  );
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
  } = viewStorage;
  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
    numberOfSelectedElements,
  } = useEntityToggle<RelationshipsStixCoreRelationshipLine_node$data>(
    LOCAL_STORAGE_KEY,
  );

  const contextFilters = buildEntityTypeBasedFilterContext('stix-core-relationship', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<RelationshipsStixCoreRelationshipsLinesPaginationQuery>(
    relationshipsStixCoreRelationshipsLinesQuery,
    queryPaginationOptions,
  );
  const renderLines = () => {
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns = {
      fromType: {
        label: 'From type',
        width: '10%',
        isSortable: false,
      },
      fromName: {
        label: 'From name',
        width: '18%',
        isSortable: false,
      },
      relationship_type: {
        label: 'Type',
        width: '10%',
        isSortable: true,
      },
      toType: {
        label: 'To type',
        width: '10%',
        isSortable: false,
      },
      toName: {
        label: 'To name',
        width: '18%',
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        width: '7%',
        isSortable: isRuntimeSort,
      },
      creator: {
        label: 'Creators',
        width: '7%',
        isSortable: isRuntimeSort,
      },
      created_at: {
        label: 'Creation date',
        width: '10%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
        width: '8%',
      },
    };
    return (
      <>
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
          exportContext={{ entity_type: 'stix-core-relationship' }}
          disableCards={true}
          iconExtension={true}
          noPadding={true}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={queryPaginationOptions}
          numberOfElements={numberOfElements}
          availableFilterKeys={[
            'relationship_type',
            'fromId',
            'toId',
            'fromTypes',
            'toTypes',
            'objectMarking',
            'created',
            'createdBy',
            'creator_id',
          ]}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <RelationshipsStixCoreRelationshipLineDummy
                        key={idx}
                        dataColumns={dataColumns}
                      />
                    ))}
                </>
              }
            >
              <RelationshipsStixCoreRelationshipsLines
                queryRef={queryRef}
                paginationOptions={queryPaginationOptions}
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
                filters={contextFilters}
                search={searchTerm}
                handleClearSelectedElements={handleClearSelectedElements}
              />
            </React.Suspense>
          )}
        </ListLines>
      </>
    );
  };
  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Data') }, { label: t_i18n('Relationships'), current: true }]} />
      {renderLines()}
    </ExportContextProvider>
  );
};

export default Relationships;
