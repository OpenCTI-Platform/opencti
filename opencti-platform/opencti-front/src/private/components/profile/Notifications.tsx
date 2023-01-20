import React, { FunctionComponent } from 'react';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import type { Filters } from '../../../components/list_lines';
import ListLines from '../../../components/list_lines/ListLines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import NotificationsLines, {
  notificationsLinesQuery,
} from './notifications/NotificationsLines';
import {
  NotificationsLinesPaginationQuery,
  NotificationsLinesPaginationQuery$variables,
} from './notifications/__generated__/NotificationsLinesPaginationQuery.graphql';
import { NotificationLineDummy } from './notifications/NotificationLine';
import ToolBar from './notifications/ToolBar';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { NotificationLine_node$data } from './notifications/__generated__/NotificationLine_node.graphql';

export const LOCAL_STORAGE_KEY_DATA_SOURCES = 'view-notifications';

const Notifications: FunctionComponent = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<NotificationsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_DATA_SOURCES,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      filters: {} as Filters,
      numberOfElements: {
        number: 0,
        symbol: '',
      },
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
  } = useEntityToggle<NotificationLine_node$data>(
    LOCAL_STORAGE_KEY_DATA_SOURCES,
  );
  const renderLines = () => {
    const { searchTerm, sortBy, orderAsc, filters, numberOfElements } = viewStorage;
    const dataColumns = {
      operation: {
        label: 'Operation',
        width: '10%',
        isSortable: false,
      },
      message: {
        label: 'Message',
        width: '45%',
        isSortable: false,
      },
      created: {
        label: 'Date',
        width: '15%',
        isSortable: true,
      },
      name: {
        label: 'Trigger',
        width: '15%',
        isSortable: true,
      },
    };
    const queryRef = useQueryLoading<NotificationsLinesPaginationQuery>(
      notificationsLinesQuery,
      paginationOptions,
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
        handleToggleSelectAll={handleToggleSelectAll}
        keyword={searchTerm}
        filters={filters}
        iconExtension={true}
        secondaryAction={true}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'is_read',
          'created_start_date',
          'created_end_date',
        ]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array.from(Array(20).keys()).map((idx) => (
                  <NotificationLineDummy
                    key={`NotificationLineDummy-${idx}`}
                    dataColumns={dataColumns}
                  />
                ))}
              </>
            }
          >
            <NotificationsLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              onLabelClick={helpers.handleAddFilter}
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
                entity_type: [{ id: 'Notification', value: 'Notification' }],
              }}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };

  return <div>{renderLines()}</div>;
};

export default Notifications;
