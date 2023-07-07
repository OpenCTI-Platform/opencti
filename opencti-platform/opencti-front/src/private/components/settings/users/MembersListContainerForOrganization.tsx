import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import { PreloadedQuery } from 'react-relay';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ColumnsLinesTitles from '../../../../components/ColumnsLinesTitles';
import {
  MembersListForOrganizationQuery,
  MembersListForOrganizationQuery$variables,
} from './__generated__/MembersListForOrganizationQuery.graphql';
import MembersListForOrganization, { membersListForOrganizationQuery } from './MembersListForOrganization';

const useStyles = makeStyles<Theme>(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '28px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

interface MembersListContainerProps {
  organizationId: string;
}

const MembersListContainerForOrganization: FunctionComponent<MembersListContainerProps> = ({ organizationId }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const { viewStorage, helpers, paginationOptions: paginationOptionsFromStorage } = usePaginationLocalStorage<MembersListForOrganizationQuery$variables>(
    `view-${organizationId}-members`,
    {
      id: organizationId,
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      count: 25,
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
    undefined,
    false,
  );
  const { searchTerm, sortBy, orderAsc } = viewStorage;
  const paginationOptions = {
    ...paginationOptionsFromStorage,
    count: 25,
  };
  const membersQueryRef = useQueryLoading<MembersListForOrganizationQuery>(
    membersListForOrganizationQuery,
    paginationOptions,
  );

  const userColumns = {
    name: {
      label: 'Name',
      width: '20%',
      isSortable: true,
    },
    user_email: {
      label: 'Email',
      width: '30%',
      isSortable: true,
    },
    firstname: {
      label: 'Firstname',
      width: '15%',
      isSortable: true,
    },
    lastname: {
      label: 'Lastname',
      width: '15%',
      isSortable: true,
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
    <Grid item={true} xs={12} style={{ marginTop: 40 }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{ float: 'left', marginRight: 12 }}
      >
        {t('Members')}
      </Typography>
      <div style={{ float: 'right', marginTop: -12 }}>
        <SearchInput
          variant="thin"
          onSubmit={helpers.handleSearch}
          keyword={searchTerm}
        />
      </div>
      <Paper
        classes={{ root: classes.paper }}
        variant="outlined"
      >
        <ColumnsLinesTitles
          dataColumns={userColumns}
          sortBy={sortBy}
          orderAsc={orderAsc}
          handleSort={helpers.handleSort}
        />
        {membersQueryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <MembersListForOrganization
              userColumns={userColumns}
              queryRef={membersQueryRef as PreloadedQuery<MembersListForOrganizationQuery>}
              paginationOptions={paginationOptions}
            />
          </React.Suspense>
        )}
      </Paper>
    </Grid>
  );
};

export default MembersListContainerForOrganization;
