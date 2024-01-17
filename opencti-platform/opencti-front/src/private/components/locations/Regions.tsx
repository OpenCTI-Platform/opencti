import React, { FunctionComponent } from 'react';
import { useFormatter } from 'src/components/i18n';
import { makeStyles } from '@mui/styles';
import type { Theme } from 'src/components/Theme';
import RegionsLines, { regionsLinesQuery } from './regions/RegionsLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import ListLines from '../../../components/list_lines/ListLines';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { RegionsLinesPaginationQuery, RegionsLinesPaginationQuery$variables } from './regions/__generated__/RegionsLinesPaginationQuery.graphql';
import RegionCreation from './regions/RegionCreation';
import { RegionLineDummy } from './regions/RegionLine';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import BreadcrumbHeader from '../../../components/BreadcrumbHeader';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    paddingBottom: 25,
    color: theme.palette.mode === 'light'
      ? theme.palette.common.black
      : theme.palette.primary.main,
    fontSize: '24px',
    fontWeight: 'bold',
  },
}));

const LOCAL_STORAGE_KEY = 'regions';

const Regions: FunctionComponent = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<RegionsLinesPaginationQuery$variables>(
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
    const queryRef = useQueryLoading<RegionsLinesPaginationQuery>(
      regionsLinesQuery,
      paginationOptions,
    );
    return (
      <>
        <BreadcrumbHeader
          path={[
            { text: t_i18n('Locations') },
            { text: t_i18n('Regions') },
          ]}
        >
          <div className={ classes.header }>{t_i18n('Regions')}</div>
        </BreadcrumbHeader>
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
          exportContext={{ entity_type: 'Region' }}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          availableFilterKeys={[
            'created',
            'createdBy',
            'name',
          ]}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <RegionLineDummy key={idx} dataColumns={dataColumns} />
                    ))}
                </>
              }
            >
              <RegionsLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={helpers.handleSetNumberOfElements}
              />
            </React.Suspense>
          )}
        </ListLines>
      </>
    );
  };
  return (
    <>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <RegionCreation paginationOptions={paginationOptions} />
      </Security>
    </>
  );
};

export default Regions;
