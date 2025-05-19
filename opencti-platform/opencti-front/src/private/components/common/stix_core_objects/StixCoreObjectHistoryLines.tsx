import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Paper from '@mui/material/Paper';
import { StixCoreObjectHistoryLinesQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLinesQuery.graphql';
import { StixCoreObjectHistoryLines_data$key } from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLines_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectHistoryLine from './StixCoreObjectHistoryLine';

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
  fragment StixCoreObjectHistoryLines_data on Query {
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
}

const StixCoreObjectHistoryLines: FunctionComponent<StixCoreObjectHistoryLinesProps> = ({
  queryRef,
  isRelationLog,
}) => {
  const { t_i18n } = useFormatter();
  const queryData = usePreloadedQuery(stixCoreObjectHistoryLinesQuery, queryRef);
  const data = useFragment<StixCoreObjectHistoryLines_data$key>(StixCoreObjectHistoryLinesFragment, queryData);
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
