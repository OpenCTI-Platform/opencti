import React, { FunctionComponent, useEffect } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import Paper from '@mui/material/Paper';
import { interval } from 'rxjs';
import { UserHistoryLinesQuery } from '@components/settings/users/__generated__/UserHistoryLinesQuery.graphql';
import { UserHistoryLines_data$key } from '@components/settings/users/__generated__/UserHistoryLines_data.graphql';
import { makeStyles } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import UserHistoryLine from './UserHistoryLine';
import { FIVE_SECONDS } from '../../../../utils/Time';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import type { Theme } from '../../../../components/Theme';

const interval$ = interval(FIVE_SECONDS);

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    marginTop: theme.spacing(1.5),
    padding: '10px 20px 10px 20px',
    borderRadius: 6,
  },
}));

export const userHistoryLinesQuery = graphql`
  query UserHistoryLinesQuery(
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
    $cursor: ID
  ) {
    ...UserHistoryLines_data
    @arguments( search: $search, orderBy: $orderBy, orderMode: $orderMode, filters: $filters, cursor: $cursor)}
`;

const userHistoryLinesFragment = graphql`
    fragment UserHistoryLines_data on Query
    @argumentDefinitions(
      search: { type: "String" }
      orderBy: { type: "LogsOrdering", defaultValue: created_at }
      orderMode: { type: "OrderingMode", defaultValue: asc }
      filters: { type: "FilterGroup" }
      cursor: { type: "ID" }
    )
    @refetchable(queryName: "UserHistoryLinesRefetchQuery") {
      logs(
        first: $first
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
        search: $search
        after: $cursor
      ) @connection(key: "Pagination_logs") {
        edges {
          node {
            id
            ...UserHistoryLine_node
          }
        }
      }
    }
  `;

interface UserHistoryLinesProps {
  isRelationLog: boolean;
  queryRef: PreloadedQuery<UserHistoryLinesQuery>;
  refetch: () => void;
}

const UserHistoryLines: FunctionComponent<UserHistoryLinesProps> = ({
  isRelationLog,
  queryRef,
  refetch,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { data } = usePreloadedPaginationFragment<
  UserHistoryLinesQuery,
  UserHistoryLines_data$key
  >({
    linesQuery: userHistoryLinesQuery,
    linesFragment: userHistoryLinesFragment,
    queryRef,
    nodePath: ['logs', 'pageInfo', 'globalCount'],
  });

  const logs = data?.logs?.edges ?? [];

  useEffect(() => {
    // Refresh
    const subscription = interval$.subscribe(() => {
      refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);

  return (
    <Paper
      classes={{ root: classes.paper }}
      variant="outlined"
      style={{ marginTop: 0 }}
    >
      {logs.length > 0 ? (
        logs.map((logEdge) => {
          const log = logEdge?.node;
          return (log
            && <UserHistoryLine key={log?.id} node={log} />
          );
        })
      ) : (
        <div style={{ display: 'table', height: '100%', width: '100%' }}>
          <span
            style={{
              display: 'table-cell',
              verticalAlign: 'middle',
              textAlign: 'center',
            }}
          >
            {isRelationLog
              ? t('No relations history about this entity.')
              : t('No history about this entity.')}
          </span>
        </div>
      )}
    </Paper>
  );
};

export default UserHistoryLines;
