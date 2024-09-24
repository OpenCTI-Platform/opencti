import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import type { Theme } from '../../../components/Theme';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { NotifiersLinesPaginationQuery, NotifiersLinesPaginationQuery$variables } from './notifiers/__generated__/NotifiersLinesPaginationQuery.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import NotifiersLines, { NotifiersLinesQuery } from './notifiers/NotifiersLines';
import { NotifierLine_node$data } from './notifiers/__generated__/NotifierLine_node.graphql';
import { NotifierLineDummy } from './notifiers/NotifierLine';
import NotifierCreation from './notifiers/NotifierCreation';
import { useFormatter } from '../../../components/i18n';
import CustomizationMenu from './CustomizationMenu';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY = 'notifiers';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
}));

const Notifiers = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<NotifiersLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: { number: 0, symbol: '', original: 0 },
      filters: emptyFilterGroup,
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
      label: 'Name',
      width: '20%',
      isSortable: true,
    },
    description: {
      label: 'Description',
      width: '60%',
      isSortable: false,
    },
  };
  const queryRef = useQueryLoading<NotifiersLinesPaginationQuery>(
    NotifiersLinesQuery,
    paginationOptions,
  );
  return (
    <div className={classes.container}>
      <CustomizationMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Customization') }, { label: t_i18n('Notifiers'), current: true }]} />
      <NotifierCreation paginationOptions={paginationOptions} />
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
        message={t_i18n(
          'There are two built-in notifiers in the platform: User Interface and Default Mailer. They are not configurable and you can create your custom ones here.',
        )}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <NotifierLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <NotifiersLines
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

export default Notifiers;
