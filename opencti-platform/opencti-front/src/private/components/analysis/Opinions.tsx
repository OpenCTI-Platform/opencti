import React, { FunctionComponent, useContext } from 'react';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import OpinionsLines, { opinionsLinesQuery } from './opinions/OpinionsLines';
import OpinionCreation from './opinions/OpinionCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import {
  OpinionsLinesPaginationQuery,
  OpinionsLinesPaginationQuery$data,
  OpinionsLinesPaginationQuery$variables,
} from './opinions/__generated__/OpinionsLinesPaginationQuery.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { OpinionLine_node$data } from './opinions/__generated__/OpinionLine_node.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { Filters } from '../../../components/list_lines';

const LOCAL_STORAGE_KEY = 'view-opinions';

interface OpinionsProps {
  objectId: string;
  authorId: string;
  onChangeOpenExports: () => void;
}

const Opinions: FunctionComponent<OpinionsProps> = ({
  objectId,
  authorId,
  onChangeOpenExports,
}) => {
  const { helper } = useContext(UserContext);
  const additionnalFilters = [];
  if (authorId) {
    additionnalFilters.push({
      key: 'createdBy',
      values: [authorId],
      operator: 'eq',
      filterMode: 'or',
    });
  }
  if (objectId) {
    additionnalFilters.push({
      key: 'objectContains',
      values: [objectId],
      operator: 'eq',
      filterMode: 'or',
    });
  }
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
    additionnalFilters,
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
    let exportContext = null;
    if (objectId) {
      exportContext = `of-entity-${objectId}`;
    } else if (authorId) {
      exportContext = `of-entity-${authorId}`;
    }
    let finalFilters = filters;
    finalFilters = {
      ...finalFilters,
      entity_type: [{ id: 'Opinion', value: 'Opinion' }],
    };
    const isRuntimeSort = helper?.isRuntimeFieldEnable() ?? false;
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
      <div>
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
          exportContext={exportContext}
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
            <QueryRenderer
              query={opinionsLinesQuery}
              variables={{ ...paginationOptions }}
              render={({ props }: { props: OpinionsLinesPaginationQuery$data }) => (
                <OpinionsLines
                  data={props}
                  paginationOptions={paginationOptions}
                  dataColumns={dataColumns}
                  initialLoading={props === null}
                  onLabelClick={storageHelpers.handleAddFilter}
                  selectedElements={selectedElements}
                  deSelectedElements={deSelectedElements}
                  onToggleEntity={onToggleEntity}
                  selectAll={selectAll}
                  setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                />
              )}
            />
          )}
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
        </ListLines>
      </div>
    );
  };

  return (
    <UserContext.Consumer>
      {() => (
        <ExportContextProvider>
          <div>
            {renderLines()}
            <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
              <OpinionCreation paginationOptions={paginationOptions}/>
            </Security>
          </div>
        </ExportContextProvider>
      )}
    </UserContext.Consumer>
  );
};
export default Opinions;
