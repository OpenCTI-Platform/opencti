import React from 'react';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import SettingsOrganizationUserCreation from './users/SettingsOrganizationUserCreation';
import EnterpriseEdition from '../common/entreprise_edition/EnterpriseEdition';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import UsersLines, { usersLinesQuery } from './users/UsersLines';
import UserCreation from './users/UserCreation';
import AccessesMenu from './AccessesMenu';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useGranted, { SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const LOCAL_STORAGE_KEY = 'users';

const Users = () => {
  const classes = useStyles();
  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      sortBy: 'name',
      orderAsc: true,
      searchTerm: '',
    },
  );
  const isSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const isAdminOrganization = useGranted([VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '20%',
        isSortable: true,
      },
      user_email: {
        label: 'Email',
        width: '25%',
        isSortable: true,
      },
      firstname: {
        label: 'Firstname',
        width: '12.5%',
        isSortable: true,
      },
      lastname: {
        label: 'Lastname',
        width: '12.5%',
        isSortable: true,
      },
      effective_confidence_level: {
        label: 'confidence',
        width: '10%',
        isSortable: false,
      },
      otp: {
        label: '2FA',
        width: '5%',
        isSortable: false,
      },
      created_at: {
        label: 'Creation date',
        width: '10%',
        isSortable: true,
      },
    };
    return (
      <ListLines
        sortBy={viewStorage.sortBy}
        orderAsc={viewStorage.orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        displayImport={false}
        secondaryAction={false}
        keyword={viewStorage.searchTerm}
      >
        <QueryRenderer
          query={usersLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <UsersLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  };

  return (
    <div className={classes.container}>
      <AccessesMenu />
      {isSetAccess || isEnterpriseEdition ? (
        renderLines()
      ) : (
        <Grid item={true} xs={12}>
          <EnterpriseEdition
            feature="Organization sharing"
          />
        </Grid>
      )}
      {isSetAccess && <UserCreation paginationOptions={paginationOptions} />}
      {!isSetAccess && isAdminOrganization && isEnterpriseEdition && (
        <SettingsOrganizationUserCreation
          paginationOptions={paginationOptions}
          variant="fab"
        />
      )}
    </div>
  );
};

export default Users;
