import React from 'react';
import {
  EventsLinesPaginationQuery,
  EventsLinesPaginationQuery$variables,
} from '@components/entities/events/__generated__/EventsLinesPaginationQuery.graphql';
import { EventLineDummy } from '@components/entities/events/EventLine';
import ListLines from '../../../components/list_lines/ListLines';
import EventsLines, { eventsLinesQuery } from './events/EventsLines';
import EventCreation from './events/EventCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../components/list_lines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'view-events';

const Events = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<EventsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: {} as Filters,
    },
  );

  const renderLines = () => {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = viewStorage;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '30%',
        isSortable: true,
      },
      event_types: {
        label: 'Types',
        width: '20%',
        isSortable: true,
      },
      start_time: {
        label: 'Start date',
        width: '15%',
        isSortable: true,
      },
      stop_time: {
        label: 'End date',
        width: '15%',
        isSortable: true,
      },
      created: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
    };
    const queryRef = useQueryLoading<EventsLinesPaginationQuery>(
      eventsLinesQuery,
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
        handleToggleExports={helpers.handleToggleExports}
        openExports={openExports}
        exportEntityType="Event"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'event_types',
          'createdBy',
          'start_time_end_date',
          'start_time_start_date',
          'stop_time_end_date',
          'stop_time_start_date',
        ]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((idx) => (
                    <EventLineDummy
                      key={idx}
                      dataColumns={dataColumns}
                    />
                  ))}
              </>
            }
          >
            <EventsLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              setNumberOfElements={helpers.handleSetNumberOfElements}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };
  return (
    <div>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <EventCreation paginationOptions={paginationOptions} />
      </Security>
    </div>
  );
};

export default Events;
