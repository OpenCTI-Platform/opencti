import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import MembersList, { membersListQuery } from './MembersList';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { MembersListQuery, MembersListQuery$variables } from './__generated__/MembersListQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';

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
  groupId: string;
}

const MembersListContainer: FunctionComponent<MembersListContainerProps> = ({ groupId }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const { viewStorage, helpers } = usePaginationLocalStorage<MembersListQuery$variables>(
    `view-${groupId}-members`,
    { searchTerm: '' },
  );
  const { searchTerm } = viewStorage;
  const groupMembersQueryRef = useQueryLoading<MembersListQuery>(
    membersListQuery,
    { id: groupId, search: searchTerm },
  );

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
        {groupMembersQueryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <MembersList queryRef={groupMembersQueryRef} />
          </React.Suspense>
        )}
      </Paper>
    </Grid>
  );
};

export default MembersListContainer;
