import React, { FunctionComponent, useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useRefetchableFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import {
  StixCoreObjectHistoryLinesQuery,
  StixCoreObjectHistoryLinesQuery$variables,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLinesQuery.graphql';
import { StixCoreObjectHistoryLines_data$key } from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLines_data.graphql';
import { interval } from 'rxjs';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectHistoryLine from './StixCoreObjectHistoryLine';
import { FIVE_SECONDS } from '../../../../utils/Time';

export const stixCoreObjectHistoryLinesQuery = graphql`
  query StixCoreObjectHistoryLinesQuery(
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    ...StixCoreObjectHistoryLines_data
  }
`;

const StixCoreObjectHistoryLinesFragment = graphql`
  fragment StixCoreObjectHistoryLines_data on Query
  @refetchable(queryName: "StixCoreObjectHistoryLinesRefetchQuery") {
    logs(
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          ...StixCoreObjectHistoryLine_node
        }
      }
    }
  }
`;

interface StixCoreObjectHistoryLinesProps {
  queryRef: PreloadedQuery<StixCoreObjectHistoryLinesQuery>,
  isRelationLog: boolean,
  paginationOptions: StixCoreObjectHistoryLinesQuery$variables,
}

const interval$ = interval(FIVE_SECONDS);

const StixCoreObjectHistoryLines: FunctionComponent<StixCoreObjectHistoryLinesProps> = ({
  queryRef,
  isRelationLog,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const queryData = usePreloadedQuery(stixCoreObjectHistoryLinesQuery, queryRef);
  const [data, refetch] = useRefetchableFragment<StixCoreObjectHistoryLinesQuery, StixCoreObjectHistoryLines_data$key>(
    StixCoreObjectHistoryLinesFragment,
    queryData,
  );

  useEffect(() => {
    // Refresh the history every interval
    const subscription = interval$.subscribe(() => {
      refetch(paginationOptions, { fetchPolicy: 'store-and-network' });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, [refetch]);

  const logs = data?.logs?.edges ?? [];
  return (
    <Paper
      style={{
        marginTop: 6,
        padding: 15,
        borderRadius: 4,
      }}
      className={'paper-for-grid'}
      variant="outlined"
    >
      {logs.length > 0 ? (
        logs.filter((l) => !!l).map((logEdge) => {
          const log = logEdge.node;
          return (
            <StixCoreObjectHistoryLine
              key={log.id}
              node={log}
              isRelation={isRelationLog}
            />
          );
        })
      ) : (
        <div
          style={{
            display: 'table',
            height: '100%',
            width: '100%',
          }}
        >
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

export default StixCoreObjectHistoryLines;
