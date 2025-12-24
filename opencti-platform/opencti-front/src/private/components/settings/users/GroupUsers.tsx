import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import { PreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import GroupUsersLines, { groupUsersLinesQuery } from './GroupUsersLines';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { GroupUsersLinesQuery, GroupUsersLinesQuery$variables } from './__generated__/GroupUsersLinesQuery.graphql';
import ColumnsLinesTitles from '../../../../components/ColumnsLinesTitles';
import { UserLineDummy } from './UserLine';
import Card from '../../../../components/common/card/Card';

interface GroupUsersProps {
  groupId: string;
}

export const initialStaticPaginationForGroupUsers = {
  searchTerm: '',
  sortBy: 'name',
  orderAsc: true,
  count: 25,
  numberOfElements: {
    number: 0,
    symbol: '',
  },
};

const GroupUsers: FunctionComponent<GroupUsersProps> = ({ groupId }) => {
  const { t_i18n } = useFormatter();
  const LOCAL_STORAGE_KEY = `group-${groupId}-users`;
  const {
    viewStorage,
    helpers,
    paginationOptions: paginationOptionsFromStorage,
  } = usePaginationLocalStorage<GroupUsersLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      id: groupId,
      ...initialStaticPaginationForGroupUsers,
    },
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
      label: 'Max Confidence',
      width: '10%',
      isSortable: false,
    },
    otp: {
      label: '2FA',
      width: '5%',
      isSortable: false,
    },
    created_at: {
      label: 'Platform creation date',
      width: '10%',
      isSortable: true,
    },
  };
  return (
    <Grid item xs={12} style={{ marginTop: 10 }}>
      <Card
        title={t_i18n('Members')}
        titleSx={{ alignItems: 'end' }}
        action={(
          <SearchInput
            variant="thin"
            onSubmit={helpers.handleSearch}
            keyword={searchTerm}
          />
        )}
      >
        <ColumnsLinesTitles
          dataColumns={dataColumns}
          sortBy={sortBy}
          orderAsc={orderAsc}
          handleSort={helpers.handleSort}
        />
        {queryRef && (
          <React.Suspense
            fallback={(
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <UserLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            )}
          >
            <GroupUsersLines
              dataColumns={dataColumns}
              queryRef={queryRef as PreloadedQuery<GroupUsersLinesQuery>}
              paginationOptions={paginationOptions}
            />
          </React.Suspense>
        )}
      </Card>
    </Grid>
  );
};

export default GroupUsers;
