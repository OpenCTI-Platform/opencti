import React, { FunctionComponent } from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import PositionCreation from './positions/PositionCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../components/list_lines';
import {
  PositionsLinesPaginationQuery,
  PositionsLinesPaginationQuery$variables,
} from './positions/__generated__/PositionsLinesPaginationQuery.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { PositionLineDummy } from './positions/PositionLine';
import PositionsLines, { positionsLinesQuery } from './positions/PositionsLines';

const LOCAL_STORAGE_KEY_POSITIONS = 'view-positions';

const Positions: FunctionComponent = () => {
  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage < PositionsLinesPaginationQuery$variables >(LOCAL_STORAGE_KEY_POSITIONS, {
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

  const {
    searchTerm,
    sortBy,
    orderAsc,
    filters,
    openExports,
    numberOfElements,
  } = viewStorage;

  const renderLines = () => {
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
    const queryRef = useQueryLoading<PositionsLinesPaginationQuery>(positionsLinesQuery, paginationOptions);

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
        exportEntityType="Position"
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
            <>{Array(20).fill(0).map((idx) => (<PositionLineDummy key={idx} dataColumns={dataColumns}/>))}</>
          }>
            <PositionsLines
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
        <PositionCreation paginationOptions={paginationOptions} />
      </Security>
    </div>
  );
};

export default Positions;
