import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import AccessesMenu from './AccessesMenu';
import { QueryRenderer } from '../../../relay/environment';
import SessionsList, { sessionsListQuery } from './SessionsList';
import SearchInput from '../../../components/SearchInput';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  parameters: {
    float: 'left',
    marginBottom: 10,
  },
}));

const LOCAL_STORAGE_KEY = 'sessions';

const Sessions = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Sessions | Security | Settings'));
  const { viewStorage, helpers } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {},
  );
  return (
    <div className={classes.container}>
      <AccessesMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Security') }, { label: t_i18n('Sessions'), current: true }]} />
      <div className={classes.parameters}>
        <div style={{ float: 'left', marginRight: 20 }}>
          <SearchInput
            variant="small"
            onSubmit={helpers.handleSearch}
            keyword={viewStorage.searchTerm ?? ''}
          />
        </div>
      </div>
      <div className="clearfix" />
      <QueryRenderer
        query={sessionsListQuery}
        render={({ props }) => {
          if (props) {
            return <SessionsList data={props} keyword={viewStorage.searchTerm ?? ''} />;
          }
          return <div />;
        }}
      />
    </div>
  );
};

export default Sessions;
