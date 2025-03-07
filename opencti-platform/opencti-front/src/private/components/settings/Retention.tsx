import React from 'react';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import { RetentionLinesPaginationQuery, RetentionLinesPaginationQuery$variables } from '@components/settings/retention/__generated__/RetentionLinesPaginationQuery.graphql';
import { RetentionLineDummy } from './retention/RetentionLine';
import ListLines from '../../../components/list_lines/ListLines';
import RetentionLines, { RetentionLinesQuery } from './retention/RetentionLines';
import RetentionCreation from './retention/RetentionCreation';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../components/i18n';
import { RETENTION_MANAGER } from '../../../utils/platformModulesHelper';
import CustomizationMenu from './CustomizationMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { DataColumns } from '../../../components/list_lines';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const LOCAL_STORAGE_KEY = 'retention';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const Retention = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Retention | Customization | Settings'));
  const { platformModuleHelpers } = useAuth();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<RetentionLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
  });
  const { searchTerm, sortBy, orderAsc } = viewStorage;
  const dataColumns = {
    name: {
      label: 'Name',
      width: '15%',
      isSortable: true,
    },
    max_retention: {
      label: 'Max retention',
      width: '15%',
      isSortable: true,
    },
    last_execution_date: {
      label: 'Last execution',
      width: '15%',
      isSortable: true,
    },
    remaining_count: {
      label: 'Remaining',
      width: '10%',
      isSortable: true,
    },
    scope: {
      label: 'Scope',
      width: '10%',
      isSortable: true,
    },
    filters: {
      label: 'Apply on',
      width: '35%',
      isSortable: false,
    },
  } as DataColumns;
  if (!platformModuleHelpers.isRetentionManagerEnable()) {
    return (
      <div className={classes.container}>
        <Alert severity="info">
          {t_i18n(platformModuleHelpers.generateDisableMessage(RETENTION_MANAGER))}
        </Alert>
        <CustomizationMenu />
      </div>
    );
  }
  const queryRef = useQueryLoading<RetentionLinesPaginationQuery>(RetentionLinesQuery, paginationOptions);
  return (
    <div className={classes.container}>
      <CustomizationMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Customization') }, { label: t_i18n('Retention'), current: true }]} />
      <ListLines
        dataColumns={dataColumns}
        handleSearch={storageHelpers.handleSearch}
        displayImport={false}
        secondaryAction={true}
        keyword={searchTerm}
        sortBy={sortBy}
        orderAsc={orderAsc}
        handleSort={storageHelpers.handleSort}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <RetentionLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <RetentionLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
            />
          </React.Suspense>
        )}
      </ListLines>
      <RetentionCreation paginationOptions={paginationOptions} />
    </div>
  );
};

export default Retention;
