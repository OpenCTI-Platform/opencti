import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import { PreloadedQuery } from 'react-relay';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import GroupUsersLines, { groupUsersLinesQuery } from './GroupUsersLines';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import {
  GroupUsersLinesQuery,
  GroupUsersLinesQuery$variables,
} from './__generated__/GroupUsersLinesQuery.graphql';
import ColumnsLinesTitles from '../../../../components/ColumnsLinesTitles';
import { UserLineDummy } from './UserLine';

const useStyles = makeStyles<Theme>(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '28px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

interface GroupUsersProps {
  groupId: string;
}

const GroupUsers: FunctionComponent<GroupUsersProps> = ({ groupId }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const {
    viewStorage,
    helpers,
    paginationOptions: paginationOptionsFromStorage,
  } = usePaginationLocalStorage<GroupUsersLinesQuery$variables>(
    `view-group-${groupId}-users`,
    {
      id: groupId,
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
    true,
  );
  const { searchTerm, sortBy, orderAsc } = viewStorage;
  const paginationOptions = {
    ...paginationOptionsFromStorage,
    count: 25,
  };
  const queryRef = useQueryLoading<GroupUsersLinesQuery>(
    groupUsersLinesQuery,
    paginationOptions,
  );
  const dataColumns = {
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
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <ColumnsLinesTitles
          dataColumns={dataColumns}
          sortBy={sortBy}
          orderAsc={orderAsc}
          handleSort={helpers.handleSort}
        />
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
            <GroupUsersLines
              dataColumns={dataColumns}
              queryRef={queryRef as PreloadedQuery<GroupUsersLinesQuery>}
              paginationOptions={paginationOptions}
            />
          </React.Suspense>
        )}
      </Paper>
    </Grid>
  );
};

export default GroupUsers;
