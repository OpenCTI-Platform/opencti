import React, { FunctionComponent } from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import PositionCreation from './positions/PositionCreation';
import { KnowledgeSecurity } from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { PositionsLinesPaginationQuery, PositionsLinesPaginationQuery$variables } from './positions/__generated__/PositionsLinesPaginationQuery.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { PositionLineDummy } from './positions/PositionLine';
import PositionsLines, { positionsLinesQuery } from './positions/PositionsLines';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY_POSITIONS = 'positions';

const Positions: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<PositionsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_POSITIONS,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: emptyFilterGroup,
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
  );
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
        label: 'Original creation date',
        width: '15%',
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        width: '15%',
        isSortable: true,
      },
    };
    const queryRef = useQueryLoading<PositionsLinesPaginationQuery>(
      positionsLinesQuery,
      paginationOptions,
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
        openExports={openExports}
        exportContext={{ entity_type: 'Position' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <PositionLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
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
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Locations') }, { label: t_i18n('Positions'), current: true }]} />
      {renderLines()}
      <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Position'>
        <PositionCreation paginationOptions={paginationOptions} />
      </KnowledgeSecurity>
    </>
  );
};

export default Positions;
