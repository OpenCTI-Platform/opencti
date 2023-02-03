import React, { FunctionComponent, useContext } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { Filters } from '../../../components/list_lines';
import {
  CasesFilter,
  FeedbacksLinesPaginationQuery,
  FeedbacksLinesPaginationQuery$variables,
} from './feedbacks/__generated__/FeedbacksLinesPaginationQuery.graphql';
import FeedbacksLines, {
  feedbacksLinesQuery,
} from './feedbacks/FeedbacksLines';
import { FeedbackLineDummy } from './feedbacks/FeedbackLine';
import { UserContext } from '../../../utils/hooks/useAuth';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { FeedbackLine_node$data } from './feedbacks/__generated__/FeedbackLine_node.graphql';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

interface CasesProps {
  inputValue?: string;
}

export const LOCAL_STORAGE_KEY_CASE = 'view-cases-feedbacks';

const Feedbacks: FunctionComponent<CasesProps> = () => {
  const classes = useStyles();
  const { helper } = useContext(UserContext);
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<FeedbacksLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_CASE,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: {} as Filters,
    },
  );
  const key: ReadonlyArray<CasesFilter> = ['case_type'];
  const finalPaginationOptions = {
    ...paginationOptions,
    filters: [
      ...(paginationOptions.filters ?? []),
      { key, values: ['feedback'] },
    ],
  };
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<FeedbackLine_node$data>(LOCAL_STORAGE_KEY_CASE);
  const renderLines = () => {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = viewStorage;
    const isRuntimeSort = helper?.isRuntimeFieldEnable();
    const dataColumns = {
      name: {
        label: 'Name',
        width: '25%',
        isSortable: true,
      },
      rating: {
        label: 'Rating',
        width: '8%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeSort ?? false,
      },
      creator: {
        label: 'Creator',
        width: '12%',
        isSortable: isRuntimeSort ?? false,
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
        width: '8%',
        isSortable: isRuntimeSort ?? false,
      },
    };
    const queryRef = useQueryLoading<FeedbacksLinesPaginationQuery>(
      feedbacksLinesQuery,
      finalPaginationOptions,
    );
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleToggleExports={helpers.handleToggleExports}
        handleToggleSelectAll={handleToggleSelectAll}
        selectAll={selectAll}
        openExports={openExports}
        exportEntityType="Case"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={finalPaginationOptions}
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
                    <FeedbackLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <FeedbacksLines
              queryRef={queryRef}
              paginationOptions={finalPaginationOptions}
              dataColumns={dataColumns}
              setNumberOfElements={helpers.handleSetNumberOfElements}
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              onToggleEntity={onToggleEntity}
              selectAll={selectAll}
            />
            <ToolBar
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              numberOfSelectedElements={numberOfSelectedElements}
              handleClearSelectedElements={handleClearSelectedElements}
              selectAll={selectAll}
              filters={{
                entity_type: [{ id: 'Case', value: 'Case' }],
                case_type: [{ id: 'feedback', value: 'feedback' }],
              }}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };

  return (
    <ExportContextProvider>
    <div className={classes.container}>
      {renderLines()}
    </div>
    </ExportContextProvider>
  );
};

export default Feedbacks;
