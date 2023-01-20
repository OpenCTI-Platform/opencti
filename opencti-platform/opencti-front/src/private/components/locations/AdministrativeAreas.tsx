import React, { FunctionComponent } from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import AdministrativeAreasLines, { administrativeAreasLinesQuery } from './administrative_areas/AdministrativeAreasLines';
import AdministrativeAreaCreation from './administrative_areas/AdministrativeAreaCreation';
import Security from '../../../utils/Security';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { AdministrativeAreaLineDummy } from './administrative_areas/AdministrativeAreaLine';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { AdministrativeAreasLinesPaginationQuery, AdministrativeAreasLinesPaginationQuery$variables } from './administrative_areas/__generated__/AdministrativeAreasLinesPaginationQuery.graphql';
import { Filters } from '../../../components/list_lines';

const AdministrativeAreas: FunctionComponent = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<AdministrativeAreasLinesPaginationQuery$variables>('view-administrative-areas', {
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

    const queryRef = useQueryLoading<AdministrativeAreasLinesPaginationQuery>(administrativeAreasLinesQuery, paginationOptions);

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
        exportEntityType="AdministrativeArea"
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
            <>{Array(20).fill(0).map((idx) => (<AdministrativeAreaLineDummy key={idx} dataColumns={dataColumns} />))}</>
          }>
            <AdministrativeAreasLines
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
        <AdministrativeAreaCreation paginationOptions={paginationOptions} />
      </Security>
    </div>
  );
};

export default AdministrativeAreas;
