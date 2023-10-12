import React, { FunctionComponent, useState } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { AddOutlined, HorizontalRule, Security } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import SettingsOrganizationUserCreation from '@components/settings/users/SettingsOrganizationUserCreation';
import { SettingsOrganization_organization$data } from '@components/settings/organizations/__generated__/SettingsOrganization_organization.graphql';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { SettingsOrganizationUsersLinesQuery, SettingsOrganizationUsersLinesQuery$variables } from './__generated__/SettingsOrganizationUsersLinesQuery.graphql';
import SettingsOrganizationUsersLines, { settingsOrganizationUsersLinesQuery } from './SettingsOrganizationUsersLines';
import { UserLineDummy } from './UserLine';
import ListLines from '../../../../components/list_lines/ListLines';
import { DataColumns } from '../../../../components/list_lines';

const useStyles = makeStyles<Theme>(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '28px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  createButton: {
    float: 'left',
    marginTop: -15,
  },
}));

interface MembersListContainerProps {
  organization: SettingsOrganization_organization$data
  isOrganizationAdmin: boolean
}

const SettingsOrganizationUsers: FunctionComponent<MembersListContainerProps> = ({ organization, isOrganizationAdmin = false }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [openAddUser, setOpenAddUser] = useState(false);
  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<SettingsOrganizationUsersLinesQuery$variables>(
    `view-organization-${organization.id}-users`,
    {
      sortBy: 'name',
      orderAsc: true,
    },
    undefined,
    true,
  );
  const { searchTerm, sortBy, orderAsc } = viewStorage;
  const queryRef = useQueryLoading<SettingsOrganizationUsersLinesQuery>(
    settingsOrganizationUsersLinesQuery,
    { ...paginationOptions, id: organization.id },
  );
  const dataColumns: DataColumns = {
    name: {
      label: 'Name',
      width: '20%',
      isSortable: true,
      render: (user) => user.name,
    },
    user_email: {
      label: 'Email',
      width: '30%',
      isSortable: true,
      render: (user) => user.user_email,
    },
    firstname: {
      label: 'Firstname',
      width: '15%',
      isSortable: true,
      render: (user) => user.firstname,
    },
    lastname: {
      label: 'Lastname',
      width: '15%',
      isSortable: true,
      render: (user) => user.lastname,
    },
    otp: {
      label: '2FA',
      width: '5%',
      isSortable: false,
      render: (user) => (
        <>
          {user.otp_activated ? (
            <Security fontSize="small" color="secondary" />
          ) : (
            <HorizontalRule fontSize="small" color="primary" />
          )}
        </>
      ),
    },
    created_at: {
      label: 'Creation date',
      width: '10%',
      isSortable: true,
      render: (user, { fd }) => fd(user.created_at),
    },
  };

  return (
    <Grid item={true} xs={12} style={{ marginTop: 40 }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{ float: 'left', marginRight: 12 }}
      >
        {t('Users')}
      </Typography>
      <div style={{ float: 'right', marginTop: -12 }}>
        <SearchInput
          variant="thin"
          onSubmit={helpers.handleSearch}
          keyword={searchTerm}
        />
      </div>
      <Tooltip title={t('Add a new member')}>
        <IconButton
          aria-label="Add"
          className={classes.createButton}
          onClick={() => setOpenAddUser(true)}
          size="large"
          color="secondary"
        >
          <AddOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
      <SettingsOrganizationUserCreation
        paginationOptions={paginationOptions}
        open={openAddUser}
        handleClose={() => setOpenAddUser(false)}
        organization={organization}
      />

      <Paper classes={{ root: classes.paper }} variant="outlined">
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          inline={true}
          secondaryAction={true}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((idx) => (
                      <UserLineDummy key={idx} dataColumns={dataColumns} />
                    ))}
                </>
              }
            >
              <SettingsOrganizationUsersLines
                dataColumns={dataColumns}
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                isOrganizationAdmin={isOrganizationAdmin}
              />
            </React.Suspense>
          )}
        </ListLines>
      </Paper>
    </Grid>
  );
};

export default SettingsOrganizationUsers;
