import React, { FunctionComponent } from 'react';
import RegionsLines, { regionsLinesQuery } from './regions/RegionsLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import ListLines from '../../../components/list_lines/ListLines';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { RegionsLinesPaginationQuery, RegionsLinesPaginationQuery$variables } from './regions/__generated__/RegionsLinesPaginationQuery.graphql';
import RegionCreation from './regions/RegionCreation';
import { Filters } from '../../../components/list_lines';
import { RegionLineDummy } from './regions/RegionLine';

const Regions: FunctionComponent = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<RegionsLinesPaginationQuery$variables>('view-regions', {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: {} as Filters,
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  });

  const renderLines = () => {
    const {
      searchTerm,
      sortBy,
      orderAsc,
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
        width: '20%',
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        width: '20%',
        isSortable: true,
      },
    };
    const queryRef = useQueryLoading<RegionsLinesPaginationQuery>(regionsLinesQuery, paginationOptions);

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
        exportEntityType="Region"
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
          <React.Suspense fallback={
            <>{[0, 1, 2].map((idx) => (<RegionLineDummy key={idx} />))}</>
          }>
            <RegionsLines
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
        <RegionCreation paginationOptions={paginationOptions} />
      </Security>
    </div>
  );
};

export default Regions;
