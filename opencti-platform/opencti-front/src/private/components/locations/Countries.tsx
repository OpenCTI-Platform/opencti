import React, { FunctionComponent } from 'react';
import CountriesLines, { countriesLinesQuery } from './countries/CountriesLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListLines from '../../../components/list_lines/ListLines';
import { KnowledgeSecurity } from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import CountryCreation from './countries/CountryCreation';
import { CountriesLinesPaginationQuery, CountriesLinesPaginationQuery$variables } from './countries/__generated__/CountriesLinesPaginationQuery.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { CountryLineDummy } from './countries/CountryLine';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY = 'countries';

const Countries: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CountriesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
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
        label: 'Original creation date',
        width: '20%',
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        width: '20%',
        isSortable: true,
      },
    };
    const queryRef = useQueryLoading<CountriesLinesPaginationQuery>(
      countriesLinesQuery,
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
        exportContext={{ entity_type: 'Country' }}
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
                    <CountryLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <CountriesLines
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
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Locations') }, { label: t_i18n('Countries'), current: true }]} />
      {renderLines()}
      <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Country'>
        <CountryCreation paginationOptions={paginationOptions} />
      </KnowledgeSecurity>
    </>
  );
};

export default Countries;
