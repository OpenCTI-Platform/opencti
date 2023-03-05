import React, { useContext } from 'react';
import Alert from '@mui/material/Alert';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import RetentionLines, {
  RetentionLinesQuery,
} from './retention/RetentionLines';
import RetentionCreation from './retention/RetentionCreation';
import { UserContext } from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../components/i18n';
import { RETENTION_MANAGER } from '../../../utils/platformModulesHelper';

const LOCAL_STORAGE_KEY = 'retention-view';

const Retention = () => {
  const { t } = useFormatter();
  const { helper } = useContext(UserContext);
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
    filters: {
      label: 'Apply on',
      width: '35%',
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
  };
  if (!helper.isRetentionManagerEnable()) {
    return (
      <Alert severity="info">
        {t(helper.generateDisableMessage(RETENTION_MANAGER))}
      </Alert>
    );
  }
  return (
    <>
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
    </>
  );
};

export default Retention;
