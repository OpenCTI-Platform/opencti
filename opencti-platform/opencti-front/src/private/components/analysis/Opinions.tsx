import React, { FunctionComponent } from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import OpinionsLines, { opinionsLinesQuery } from './opinions/OpinionsLines';
import OpinionCreation from './opinions/OpinionCreation';
import Security from '../../../utils/Security';
import {
  KNOWLEDGE_KNPARTICIPATE,
  KNOWLEDGE_KNUPDATE,
} from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import {
  OpinionsLinesPaginationQuery,
  OpinionsLinesPaginationQuery$variables,
} from './opinions/__generated__/OpinionsLinesPaginationQuery.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { OpinionLine_node$data } from './opinions/__generated__/OpinionLine_node.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { Filters } from '../../../components/list_lines';
import { OpinionLineDummy } from './opinions/OpinionLine';

const LOCAL_STORAGE_KEY = 'view-opinions';

interface OpinionsProps {
  objectId?: string;
  authorId?: string;
  onChangeOpenExports: () => void;
}

const Opinions: FunctionComponent<OpinionsProps> = ({
  onChangeOpenExports,
}) => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<OpinionsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: {} as Filters,
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
      count: 25,
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
  } = useEntityToggle<OpinionLine_node$data>('view-opinions');

  const queryRef = useQueryLoading<OpinionsLinesPaginationQuery>(
    opinionsLinesQuery,
    paginationOptions,
  );
  const renderLines = () => {
    let finalFilters = filters;
    finalFilters = {
      ...finalFilters,
      entity_type: [{ id: 'Opinion', value: 'Opinion' }],
    };
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns = {
      opinion: {
        label: 'Opinion',
        width: '35%',
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
      created: {
        label: 'Date',
        width: '10%',
        isSortable: true,
      },
      x_opencti_workflow_id: {
        label: 'Status',
        width: '8%',
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
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          openExports={openExports}
          noPadding={typeof onChangeOpenExports === 'function'}
          exportEntityType="Opinion"
          keyword={searchTerm}
          filters={filters}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          iconExtension={true}
          availableFilterKeys={[
            'x_opencti_workflow_id',
            'labelledBy',
            'createdBy',
            'creator',
            'markedBy',
            'confidence',
            'created_start_date',
            'created_end_date',
          ]}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((idx) => (
                      <OpinionLineDummy key={idx} dataColumns={dataColumns} />
                    ))}
                </>
              }
            >
              <OpinionsLines
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
            </React.Suspense>
          )}
        </ListLines>
        <ToolBar
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          numberOfSelectedElements={numberOfSelectedElements}
          selectAll={selectAll}
          search={searchTerm}
          filters={finalFilters}
          handleClearSelectedElements={handleClearSelectedElements}
          type="Opinion"
        />
      </>
    );
  };

  return (
    <ExportContextProvider>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
        <OpinionCreation paginationOptions={paginationOptions} />
      </Security>
    </ExportContextProvider>
  );
};
export default Opinions;
