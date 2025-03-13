import React, { FunctionComponent, useEffect } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import Paper from '@mui/material/Paper';
import { interval } from 'rxjs';
import { UserHistoryLinesQuery, UserHistoryLinesQuery$variables } from '@components/settings/users/__generated__/UserHistoryLinesQuery.graphql';
import { UserHistoryLines_data$key } from '@components/settings/users/__generated__/UserHistoryLines_data.graphql';
import { makeStyles } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import UserHistoryLine from './UserHistoryLine';
import { FIVE_SECONDS } from '../../../../utils/Time';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import type { Theme } from '../../../../components/Theme';

const interval$ = interval(FIVE_SECONDS);

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    marginTop: theme.spacing(1.5),
    padding: '10px 20px 10px 20px',
    borderRadius: 4,
    maxHeight: 600,
    overflowY: 'auto',
  },
}));

export const userHistoryLinesQuery = graphql`
  query UserHistoryLinesQuery(
    $types: [String!]
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
    $cursor: ID
  ) {
    ...UserHistoryLines_data
    @arguments( types: $types, search: $search, orderBy: $orderBy, orderMode: $orderMode, filters: $filters, cursor: $cursor)}
`;

const userHistoryLinesFragment = graphql`
    fragment UserHistoryLines_data on Query
    @argumentDefinitions(
      types: { type: "[String!]" }
      search: { type: "String" }
      orderBy: { type: "LogsOrdering", defaultValue: created_at }
      orderMode: { type: "OrderingMode", defaultValue: asc }
      filters: { type: "FilterGroup" }
      cursor: { type: "ID" }
    )
    @refetchable(queryName: "UserHistoryLinesRefetchQuery") {
      audits(
        types: $types
        first: $first
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
        search: $search
        after: $cursor
      ) @connection(key: "Pagination_audits") {
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
  queryArgs: UserHistoryLinesQuery$variables;
  refetch: (args: UserHistoryLinesQuery$variables) => void;
}

const UserHistoryLines: FunctionComponent<UserHistoryLinesProps> = ({
  isRelationLog,
  queryRef,
  queryArgs,
  refetch,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { data } = usePreloadedPaginationFragment<
  UserHistoryLinesQuery,
  UserHistoryLines_data$key
  >({
    linesQuery: userHistoryLinesQuery,
    linesFragment: userHistoryLinesFragment,
    queryRef,
    nodePath: ['audits', 'pageInfo', 'globalCount'],
  });
  const audits = data?.audits?.edges ?? [];
  useEffect(() => {
    // Refresh
    const subscription = interval$.subscribe(() => {
      refetch(queryArgs);
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, [queryArgs]);

  return (
    <Paper
      classes={{ root: classes.paper }}
      variant="outlined"
      style={{ marginTop: 0, minHeight: 500 }}
      className={'paper-for-grid'}
    >
      {audits.length > 0 ? (
        audits.map((auditEdge) => {
          const audit = auditEdge?.node;
          return (audit
            && <UserHistoryLine key={audit?.id} node={audit} />
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
              ? t_i18n('No relations history about this entity.')
              : t_i18n('No history about this entity.')}
          </span>
        </div>
      )}
    </Paper>
  );
};

export default UserHistoryLines;
