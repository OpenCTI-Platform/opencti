import React, { useRef, useState, useEffect } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import { CSVLink } from 'react-csv';
import type { Theme } from '../../../../../../components/Theme';
import ListLines from '../../../../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../../../../utils/hooks/useEntityToggle';
import { SearchLogLinesPaginationQuery, SearchLogLinesPaginationQuery$variables } from './__generated__/SearchLogLinesPaginationQuery.graphql';
import useQueryLoading from '../../../../../../utils/hooks/useQueryLoading';
import SearchLogLines, { SearchLogLinesQuery } from './SearchLogLines';
import useAuth from '../../../../../../utils/hooks/useAuth';
import { useFormatter } from '../../../../../../components/i18n';
import { emptyFilterGroup } from '../../../../../../utils/filters/filtersUtils';
import useConnectedDocumentModifier from '../../../../../../utils/hooks/useConnectedDocumentModifier';
import { SearchLogLineDummy } from './SearchLogLine';
import { SearchLogLine_node$data } from './__generated__/SearchLogLine_node.graphql';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const LOCAL_STORAGE_KEY = 'searchlog';

const SearchLog = () => {
  const classes = useStyles();
  const csvLink = useRef<
  CSVLink & HTMLAnchorElement & { link: HTMLAnchorElement }
  >(null);
  const hasPageRendered = useRef(false);
  const [loading] = useState(true);
  const { settings } = useAuth();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Events | Activity | Settings'));

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<SearchLogLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: { number: 0, symbol: '', original: 0 },
      filters: emptyFilterGroup,
      searchTerm: '',
      sortBy: 'timestamp',
      orderAsc: false,
      openExports: false,
      types: ['LogSearch'],
      count: 25,
    },
  );
  const { numberOfElements, filters, searchTerm, sortBy, orderAsc, types } = viewStorage;
  const { selectedElements, deSelectedElements, selectAll, onToggleEntity } = useEntityToggle<SearchLogLine_node$data>(LOCAL_STORAGE_KEY);
  const dataColumns = {
    timestamp: {
      label: 'Timestamp',
      width: '15%',
      isSortable: true,
    },
    user: {
      label: 'User',
      width: '10%',
      isSortable: false,
    },
    organization: {
      label: 'Organization',
      width: '10%',
      isSortable: true,
    },
    groups: {
      label: 'Groups',
      width: '15%',
      isSortable: true,
    },
    search_location: {
      label: 'Search location',
      width: '15%',
      isSortable: true,
    },
    search: {
      label: 'Search Term',
      width: '25%',
      isSortable: true,
    },
    result_count: {
      label: 'Result Count',
      width: '10%',
      isSortable: true,
    },
  };
  const queryRef = useQueryLoading<SearchLogLinesPaginationQuery>(
    SearchLogLinesQuery,
    paginationOptions,
  );
  useEffect(() => {
    if (!loading && hasPageRendered.current) {
      csvLink?.current?.link?.click();
    }
    hasPageRendered.current = true;
  }, [loading]);
  return (
    <div className={classes.container} data-testid="search-log-page">
      {settings.platform_demo && (
        <Alert severity="info" variant="outlined" style={{ marginBottom: 30 }}>
          {t_i18n(
            'This platform is running in demo mode, all names in the activity and search logs are redacted.',
          )}
        </Alert>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <ListLines
          helpers={storageHelpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={storageHelpers.handleSearch}
          handleAddFilter={storageHelpers.handleAddFilter}
          handleRemoveFilter={storageHelpers.handleRemoveFilter}
          handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
          handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
          selectAll={selectAll}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          entityTypes={types}
          disableLogging={true}
        >
          {queryRef && (
            <React.Suspense
              fallback={(
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <SearchLogLineDummy key={idx} dataColumns={dataColumns} />
                    ))}
                </>
              )}
            >
              <SearchLogLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                onLabelClick={storageHelpers.handleAddFilter}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
              />
            </React.Suspense>
          )}
        </ListLines>
      </div>
    </div>
  );
};

export default SearchLog;
