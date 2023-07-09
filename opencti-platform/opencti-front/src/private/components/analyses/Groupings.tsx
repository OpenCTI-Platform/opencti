import React, { FunctionComponent } from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import GroupingsLines, {
  groupingsLinesQuery,
} from './groupings/GroupingsLines';
import GroupingCreation from './groupings/GroupingCreation';
import ToolBar from '../data/ToolBar';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import {
  GroupingsLinesPaginationQuery,
  GroupingsLinesPaginationQuery$variables,
} from './groupings/__generated__/GroupingsLinesPaginationQuery.graphql';
import { GroupingLine_node$data } from './groupings/__generated__/GroupingLine_node.graphql';
import { GroupingLineDummy } from './groupings/GroupingLine';

const LOCAL_STORAGE_KEY = 'view-groupings';

interface GroupingsProps {
  objectId: string;
  authorId: string;
  onChangeOpenExports: () => void;
  match: { params: { groupingContext: string } };
}

const Groupings: FunctionComponent<GroupingsProps> = ({
  objectId,
  authorId,
  onChangeOpenExports,
}) => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
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
  } = usePaginationLocalStorage<GroupingsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: { number: 0, symbol: '', original: 0 },
      filters: {},
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
  } = useEntityToggle<GroupingLine_node$data>('view-groupings');
  const queryRef = useQueryLoading<GroupingsLinesPaginationQuery>(
    groupingsLinesQuery,
    paginationOptions,
  );
  const renderLines = () => {
    let exportContext = null;
    if (objectId) {
      exportContext = `of-entity-${objectId}`;
    } else if (authorId) {
      exportContext = `of-entity-${authorId}`;
    }
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = (numberOfElements?.original ?? 0)
        - Object.keys(deSelectedElements || {}).length;
    }
    let finalFilters = filters;
    finalFilters = {
      ...finalFilters,
      entity_type: [{ id: 'Grouping', value: 'Grouping' }],
    };
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '25%',
        isSortable: true,
      },
      context: {
        label: 'Context',
        width: '8%',
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
          openExports={openExports}
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          noPadding={typeof onChangeOpenExports === 'function'}
          exportEntityType="Grouping"
          exportContext={exportContext}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          iconExtension={true}
          availableFilterKeys={[
            'context',
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
                      <GroupingLineDummy key={idx} dataColumns={dataColumns} />
                    ))}
                </>
              }
            >
              <GroupingsLines
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
          type="Grouping"
        />
      </>
    );
  };
  return (
    <>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <GroupingCreation paginationOptions={paginationOptions} />
      </Security>
    </>
  );
};

export default Groupings;
