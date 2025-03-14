import { v4 as uuid } from 'uuid';
import React, { FunctionComponent, useEffect, useState } from 'react';
import Typography from '@mui/material/Typography';
import { useQueryLoader } from 'react-relay';
import { LogsOrdering, OrderingMode, UserHistoryLinesQuery, UserHistoryLinesQuery$variables } from '@components/settings/users/__generated__/UserHistoryLinesQuery.graphql';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { StorageOutlined } from '@mui/icons-material';
import { VectorRadius } from 'mdi-material-ui';
import { Link } from 'react-router-dom';
import { GqlFilterGroup } from '../../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import SearchInput from '../../../../components/SearchInput';
import UserHistoryLines, { userHistoryLinesQuery } from './UserHistoryLines';
import useGranted, { KNOWLEDGE, SETTINGS_SECURITYACTIVITY } from '../../../../utils/hooks/useGranted';

const createdByUserRedirectButton = {
  float: 'left',
  marginTop: '-15px',
};

interface UserHistoryProps {
  userId: string,
}

const UserHistory: FunctionComponent<UserHistoryProps> = ({
  userId,
}) => {
  const { t_i18n } = useFormatter();
  const [entitySearchTerm, setEntitySearchTerm] = useState<string>('');
  const isGrantedToAudit = useGranted([SETTINGS_SECURITYACTIVITY]);
  const isGrantedToKnowledge = useGranted([KNOWLEDGE]);
  const handleSearchEntity = (value: string) => {
    setEntitySearchTerm(value);
  };
  const [queryRef, loadQuery] = useQueryLoader<UserHistoryLinesQuery>(userHistoryLinesQuery);
  let historyTypes = ['History'];
  if (isGrantedToAudit && !isGrantedToKnowledge) {
    historyTypes = ['Activity'];
  } else if (isGrantedToAudit && isGrantedToKnowledge) {
    historyTypes = ['History', 'Activity'];
  }
  const queryArgs = {
    types: historyTypes,
    filters: {
      mode: 'or',
      filterGroups: [],
      filters: [
        { key: ['user_id'], values: [userId], operator: 'wildcard', mode: 'or' },
        { key: ['context_data.id'], values: [userId], operator: 'wildcard', mode: 'or' },
      ],
    } as GqlFilterGroup,
    first: 500,
    orderBy: 'timestamp' as LogsOrdering,
    orderMode: 'desc' as OrderingMode,
    search: entitySearchTerm,
  };

  // Entities and relationships redirection filters
  const technicalCreatorFilters = JSON.stringify({
    mode: 'and',
    filterGroups: [],
    filters: [
      {
        key: 'creator_id',
        values: [
          userId,
        ],
        operator: 'eq',
        mode: 'or',
        id: uuid(), // because filters in the URL
      },
    ],
  });
  useEffect(() => {
    loadQuery(queryArgs, { fetchPolicy: 'store-and-network' });
  }, [entitySearchTerm]);
  const refetch = (args: UserHistoryLinesQuery$variables) => {
    loadQuery(args, { fetchPolicy: 'store-and-network' });
  };
  return (
    <>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('History')}
      </Typography>
      <div style={{ float: 'right', marginTop: -12 }}>
        <SearchInput
          variant="thin"
          onSubmit={handleSearchEntity}
          keyword={entitySearchTerm}
        />
      </div>
      <Tooltip title={t_i18n('View all entities created by user')}>
        <IconButton
          sx={createdByUserRedirectButton}
          component={Link}
          to={`/dashboard/search/knowledge/?filters=${encodeURIComponent(technicalCreatorFilters)}`}
          size="large"
          color="primary"
        >
          <StorageOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
      <Tooltip title={t_i18n('View all relationships created by user')}>
        <IconButton
          sx={createdByUserRedirectButton}
          component={Link}
          to={`/dashboard/data/relationships/?filters=${encodeURIComponent(technicalCreatorFilters)}`}
          size="large"
          color="primary"
        >
          <VectorRadius fontSize="small" />
        </IconButton>
      </Tooltip>
      <div className="clearfix" />
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <UserHistoryLines
            queryRef={queryRef}
            queryArgs={queryArgs}
            isRelationLog={false}
            refetch={refetch}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </>
  );
};

export default UserHistory;
