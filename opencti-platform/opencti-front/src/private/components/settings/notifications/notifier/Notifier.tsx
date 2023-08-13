import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import NotificationMenu from '../../NotificationMenu';
import { Theme } from '../../../../../components/Theme';
import ListLines from '../../../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../../../utils/hooks/useEntityToggle';
import {
  NotifierLinesPaginationQuery,
  NotifierLinesPaginationQuery$variables,
} from './__generated__/NotifierLinesPaginationQuery.graphql';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import NotifierLines, { NotifierLinesQuery } from './NotifierLines';
import { NotifierLine_node$data } from './__generated__/NotifierLine_node.graphql';
import { NotifierLineDummy } from './NotifierLine';
import NotifierCreation from './NotifierCreation';
import { useFormatter } from '../../../../../components/i18n';

const LOCAL_STORAGE_KEY = 'view-notifier';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
}));

const Notifier = () => {
  const classes = useStyles();
  const { t } = useFormatter();

  const { viewStorage, paginationOptions, helpers: storageHelpers } = usePaginationLocalStorage<NotifierLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: { number: 0, symbol: '', original: 0 },
      filters: {},
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
      count: 25,
    },
  );

  const { numberOfElements, filters, searchTerm, sortBy, orderAsc } = viewStorage;
  const { selectedElements, deSelectedElements, selectAll, onToggleEntity } = useEntityToggle<NotifierLine_node$data>(LOCAL_STORAGE_KEY);
  const dataColumns = {
    connector: {
      label: 'Connector',
      width: '20%',
      isSortable: true,
    },
    name: {
      label: 'name',
      width: '20%',
      isSortable: true,
    },
    description: {
      label: 'description',
      width: '60%',
      isSortable: false,
    },
  };
  const queryRef = useQueryLoading<NotifierLinesPaginationQuery>(NotifierLinesQuery, paginationOptions);

  return (
    <div className={classes.container}>
      <NotificationMenu />
      <NotifierCreation paginationOptions={paginationOptions} />
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={storageHelpers.handleSort}
        handleSearch={storageHelpers.handleSearch}
        handleAddFilter={storageHelpers.handleAddFilter}
        handleRemoveFilter={storageHelpers.handleRemoveFilter}
        selectAll={selectAll}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'created_start_date',
          'created_end_date',
        ]}
        message={t('There are two builtins notifier in the platform: User Interface and Default Mailer. They are not configurable and you can create your custom ones here.')}
      >
        {queryRef && (
          <React.Suspense fallback={<>{Array(20).fill(0).map((idx) => (<NotifierLineDummy key={idx} dataColumns={dataColumns} />))}</>}>
            <NotifierLines
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
  );
};

export default Notifier;
