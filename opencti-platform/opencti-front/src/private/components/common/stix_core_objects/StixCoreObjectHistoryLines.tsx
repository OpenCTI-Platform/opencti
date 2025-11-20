import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useRefetchableFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import {
  StixCoreObjectHistoryLinesQuery,
  StixCoreObjectHistoryLinesQuery$variables,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLinesQuery.graphql';
import { StixCoreObjectHistoryLines_data$key } from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLines_data.graphql';
import List from '@mui/material/List';
import StixCoreObjectHistoryLine from '@components/common/stix_core_objects/StixCoreObjectHistoryLine';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import ListItem from '@mui/material/ListItem';
import { ListItemButton } from '@mui/material';
import Typography from '@mui/material/Typography';
import Drawer from '../drawer/Drawer';
import useInterval from '../../../../utils/hooks/useInterval';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';

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
  const [open, setOpen] = useState(false);
  useInterval(() => {
    // Refresh the history every interval
    refetch(paginationOptions, { fetchPolicy: 'store-and-network' });
  }, FIVE_SECONDS);
  const logs = data?.logs?.edges ?? [];

  return (
    <Paper
      style={{
        borderRadius: 4,
      }}
      className={'paper-for-grid'}
      variant="outlined"
    >
      {logs.length > 0 ? (
        <List style={{ margin: 0 }}>
          {logs.filter((l) => !!l).map((logEdge) => {
            const log = logEdge.node;
            return (
              <React.Fragment key={log.id}>
                <ListItem
                  dense={true}
                  divider={true}
                  disablePadding
                  secondaryAction={
                    <>
                      <Tooltip title={t_i18n('Browse the link')}>
                        <IconButton
                          onClick={() => setOpen(true)
                          }
                          size="large"
                          color="primary"
                        >
                        </IconButton>
                      </Tooltip>
                    </>
                  }
                >
                  <ListItemButton
                    style={{ margin: 0, height: 60 }}
                    onClick={() => setOpen(true)}
                  >
                    <StixCoreObjectHistoryLine
                      key={log.id}
                      node={log}
                      isRelation={isRelationLog}
                    />

                  </ListItemButton>
                  <Drawer
                    open={open}
                    title={('Knowledge log detail')}
                    onClose={() => setOpen(false)}
                  >
                    <>
                      <div>
                        <Typography variant="h4" gutterBottom={true}>
                          {('Message')}
                        </Typography>
                      </div>
                      <Typography variant="h4" gutterBottom={true}>
                        {('Details')}
                      </Typography>
                    </>
                  </Drawer>
                </ListItem>
              </React.Fragment>
            );
          })
          }
        </List>
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
