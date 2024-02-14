import React from 'react';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import RetentionLines, { RetentionLinesQuery } from './retention/RetentionLines';
import RetentionCreation from './retention/RetentionCreation';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../components/i18n';
import { RETENTION_MANAGER } from '../../../utils/platformModulesHelper';
import CustomizationMenu from './CustomizationMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY = 'retention';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const Retention = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { platformModuleHelpers } = useAuth();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage(LOCAL_STORAGE_KEY, {
    searchTerm: '',
  });
  const dataColumns = {
    name: {
      label: 'Name',
      width: '15%',
    },
    retention: {
      label: 'Max retention',
      width: '20%',
    },
    last_execution_date: {
      label: 'Last execution',
      width: '20%',
    },
    remaining_count: {
      label: 'Remaining',
      width: '10%',
    },
    filters: {
      label: 'Apply on',
      width: '35%',
    },
  };
  if (!platformModuleHelpers.isRetentionManagerEnable()) {
    return (
      <div>
        <Alert severity="info">
          {t_i18n(platformModuleHelpers.generateDisableMessage(RETENTION_MANAGER))}
        </Alert>
        <CustomizationMenu />
      </div>
    );
  }
  return (
    <div className={classes.container}>
      <CustomizationMenu />
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Customization') }, { label: t_i18n('Retention'), current: true }]} />
      <ListLines
        dataColumns={dataColumns}
        handleSearch={storageHelpers.handleSearch}
        displayImport={false}
        secondaryAction={true}
        keyword={viewStorage.searchTerm}
      >
        <QueryRenderer
          query={RetentionLinesQuery}
          variables={paginationOptions}
          render={({ props }) => (
            <RetentionLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
      <RetentionCreation paginationOptions={paginationOptions} />
    </div>
  );
};

export default Retention;
