import React from 'react';
import * as R from 'ramda';
import {
  RelationshipsStixCoreRelationshipsLinesPaginationQuery,
  RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables,
} from '@components/data/relationships/__generated__/RelationshipsStixCoreRelationshipsLinesPaginationQuery.graphql';
import {
  RelationshipsStixCoreRelationshipLine_node$data,
} from '@components/data/relationships/__generated__/RelationshipsStixCoreRelationshipLine_node.graphql';
import {
  RelationshipsStixCoreRelationshipLineDummy,
} from '@components/data/relationships/RelationshipsStixCoreRelationshipLine';
import ListLines from '../../../components/list_lines/ListLines';
import RelationshipsStixCoreRelationshipsLines, {
  relationshipsStixCoreRelationshipsLinesQuery,
} from './relationships/RelationshipsStixCoreRelationshipsLines';
import useAuth from '../../../utils/hooks/useAuth';
import ToolBar from './ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../components/list_lines';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'view-relationships';

const Relationships = () => {
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
      filters: {} as Filters,
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
  } = useEntityToggle<RelationshipsStixCoreRelationshipLine_node$data>(LOCAL_STORAGE_KEY);
  const queryRef = useQueryLoading<RelationshipsStixCoreRelationshipsLinesPaginationQuery>(
    relationshipsStixCoreRelationshipsLinesQuery,
    paginationOptions,
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
              exportEntityType="stix-core-relationship"
              disableCards={true}
              secondaryAction={true}
              iconExtension={true}
              noPadding={true}
              keyword={searchTerm}
              filters={filters}
              paginationOptions={paginationOptions}
              numberOfElements={numberOfElements}
              availableFilterKeys={[
                'relationship_type',
                'fromId',
                'toId',
                'fromTypes',
                'toTypes',
                'markedBy',
                'created_start_date',
                'created_end_date',
                'createdBy',
                'creator',
              ]}
            >
            {queryRef && (
                  <React.Suspense
                    fallback={
                      <>
                        {Array(20)
                          .fill(0)
                          .map((idx) => (
                            <RelationshipsStixCoreRelationshipLineDummy key={idx} dataColumns={dataColumns} />
                          ))}
                      </>
                    }
                  >
                  <RelationshipsStixCoreRelationshipsLines
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
                    filters={R.assoc(
                      'entity_type',
                      [
                        {
                          id: 'stix-core-relationship',
                          value: 'stix-core-relationship',
                        },
                      ],
                      filters,
                    )}
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
        {renderLines()}
      </ExportContextProvider>
  );
};

export default Relationships;
