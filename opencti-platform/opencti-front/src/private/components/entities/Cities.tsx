import React, { FunctionComponent } from 'react';
import { convertFilters } from '../../../utils/ListParameters';
import ListLines from '../../../components/list_lines/ListLines';
import CitiesLines, { citiesLinesQuery } from './cities/CitiesLines';
import CityCreation from './cities/CityCreation';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';
import useLocalStorage, { localStorageToPaginationOptions } from '../../../utils/hooks/useLocalStorage';
import {
  CitiesLinesPaginationQuery,
  CitiesLinesPaginationQuery$variables,
} from './cities/__generated__/CitiesLinesPaginationQuery.graphql';
import type { Filters } from '../../../components/list_lines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../components/Loader';

const Cities: FunctionComponent = () => {
  const [viewStorage, _, storageHelpers] = useLocalStorage('view-cities', {
    sortBy: 'name',
    orderAsc: true,
    searchTerm: '',
    openExports: false,
    filters: {},
    numberOfElements: { number: 0, symbol: '' },
  });
  const finalFilters = convertFilters(viewStorage.filters) as unknown as Filters;
  const paginationOptions = localStorageToPaginationOptions<CitiesLinesPaginationQuery$variables>({
    ...viewStorage,
    filters: finalFilters,
    count: 25,
  });

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
        width: '60%',
        isSortable: true,
      },
      created: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        width: '15%',
        isSortable: true,
      },
    };

    const queryRef = useQueryLoading<CitiesLinesPaginationQuery>(citiesLinesQuery, paginationOptions);

    return (
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
        exportEntityType="City"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'created_start_date',
          'created_end_date',
          'createdBy',
        ]}
      >
        {queryRef && (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <CitiesLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              setNumberOfElements={storageHelpers.handleSetNumberOfElements}
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
        <CityCreation paginationOptions={paginationOptions} />
      </Security>
    </div>
  );
};

export default Cities;
