import React, { FunctionComponent, Suspense } from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import FeedbacksLines, { feedbacksLinesQuery } from './feedbacks/FeedbacksLines';
import { FeedbackLineDummy } from './feedbacks/FeedbackLine';
import useAuth from '../../../utils/hooks/useAuth';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { FeedbacksLinesPaginationQuery, FeedbacksLinesPaginationQuery$variables } from './feedbacks/__generated__/FeedbacksLinesPaginationQuery.graphql';
import { FeedbackLine_node$data } from './feedbacks/__generated__/FeedbackLine_node.graphql';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

interface FeedbacksProps {
  inputValue?: string;
}

export const LOCAL_STORAGE_KEY_FEEDBACK = 'feedbacks';

const Feedbacks: FunctionComponent<FeedbacksProps> = () => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<FeedbacksLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_FEEDBACK,
    {
      numberOfElements: {
        number: 0,
        symbol: '',
      },
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: emptyFilterGroup,
    },
  );
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<FeedbackLine_node$data>(LOCAL_STORAGE_KEY_FEEDBACK);
  const renderLines = () => {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = viewStorage;
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
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
        label: 'Original creation date',
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
        isSortable: isRuntimeSort,
      },
    };

    const contextFilters = useBuildEntityTypeBasedFilterContext('Feedback', filters);
    const queryPaginationOptions = {
      ...paginationOptions,
      filters: contextFilters,
    } as unknown as FeedbacksLinesPaginationQuery$variables;
    const queryRef = useQueryLoading<FeedbacksLinesPaginationQuery>(
      feedbacksLinesQuery,
      queryPaginationOptions,
    );

    return (
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        handleToggleExports={helpers.handleToggleExports}
        handleToggleSelectAll={handleToggleSelectAll}
        selectAll={selectAll}
        openExports={openExports}
        exportContext={{ entity_type: 'Feedback' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={queryPaginationOptions}
        numberOfElements={numberOfElements}
        iconExtension={true}
      >
        {queryRef && (
          <Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <FeedbackLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <FeedbacksLines
              queryRef={queryRef}
              paginationOptions={queryPaginationOptions}
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
              type="Feedback"
              filters={contextFilters}
            />
          </Suspense>
        )}
      </ListLines>
    );
  };
  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Cases') }, { label: t_i18n('Requests for takedown'), current: true }]} />
      {renderLines()}
    </ExportContextProvider>
  );
};

export default Feedbacks;
