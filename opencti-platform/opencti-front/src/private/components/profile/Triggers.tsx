import React, { FunctionComponent } from 'react';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import type { Filters } from '../../../components/list_lines';
import ListLines from '../../../components/list_lines/ListLines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import TriggersLines, { triggersLinesQuery } from './triggers/TriggersLines';
import {
  TriggersLinesPaginationQuery,
  TriggersLinesPaginationQuery$variables,
} from './triggers/__generated__/TriggersLinesPaginationQuery.graphql';
import { TriggerLineDummy } from './triggers/TriggerLine';
import TriggerCreation from './triggers/TriggerCreation';

export const LOCAL_STORAGE_KEY_DATA_SOURCES = 'view-triggers';

const Triggers: FunctionComponent = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<TriggersLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_DATA_SOURCES,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      filters: {} as Filters,
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
  );
  const renderLines = () => {
    const { searchTerm, sortBy, orderAsc, filters, numberOfElements } = viewStorage;
    const dataColumns = {
      trigger_type: {
        label: 'Type',
        width: '10%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '15%',
        isSortable: true,
      },
      outcomes: {
        label: 'Notification',
        width: '20%',
        isSortable: true,
      },
      event_types: {
        label: 'Triggering on',
        width: '20%',
        isSortable: false,
      },
      filters: {
        label: 'Details',
        width: '30%',
        isSortable: false,
      },
    };
    const queryRef = useQueryLoading<TriggersLinesPaginationQuery>(
      triggersLinesQuery,
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
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array.from(Array(20).keys()).map((idx) => (
                  <TriggerLineDummy
                    key={`TriggerLineDummy-${idx}`}
                    dataColumns={dataColumns}
                  />
                ))}
              </>
            }
          >
            <TriggersLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              onLabelClick={helpers.handleAddFilter}
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
      <TriggerCreation paginationOptions={paginationOptions} />
    </div>
  );
};

export default Triggers;
