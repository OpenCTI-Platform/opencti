import React, { useState } from 'react';
import { graphql, usePreloadedQuery, useRefetchableFragment } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import ListItem from '@mui/material/ListItem';
import { ListItemButton } from '@mui/material';
import List from '@mui/material/List';
import HistoryDrawer from '@components/common/drawer/HistoryDrawer';
import StixCoreRelationshipHistoryLine from '@components/common/stix_core_relationships/StixCoreRelationshipHistoryLine';
import { useFormatter } from '../../../../components/i18n';
import useInterval from '../../../../utils/hooks/useInterval';
import { FIVE_SECONDS } from '../../../../utils/Time';
import Card from '../../../../components/common/card/Card';

export const stixCoreRelationshipHistoryLinesQuery = graphql`
  query StixCoreRelationshipHistoryLinesQuery(
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    ...StixCoreRelationshipHistoryLines_data
  }
`;

const StixCoreRelationshipHistoryLinesFragment = graphql`
  fragment StixCoreRelationshipHistoryLines_data on Query
  @refetchable(queryName: "StixCoreRelationshipHistoryLinesRefetchQuery")
  {
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
          ...StixCoreRelationshipHistoryLine_node
        }
      }
    }
  }
`;

const StixCoreRelationshipHistoryLines = ({ queryRef, isRelationLog, paginationOptions }) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null);
  const queryData = usePreloadedQuery(stixCoreRelationshipHistoryLinesQuery, queryRef);
  const [data, refetch] = useRefetchableFragment(
    StixCoreRelationshipHistoryLinesFragment, queryData,
  );

  useInterval(() => {
    // Refresh the history every interval
    refetch(paginationOptions, { fetchPolicy: 'store-and-network' });
  }, FIVE_SECONDS);
  const logs = data?.logs.edges ?? [];

  const handleOpen = (log) => {
    setSelectedLog(log);
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
    setSelectedLog(undefined);
  };

  return (
    <Card title={t_i18n('Most recent history')}>
      {logs.length > 0 ? (
        <List>
          {logs.map((logEdge) => {
            const log = logEdge.node;
            return (
              <React.Fragment key={log.id}>
                <ListItem
                  dense={true}
                  divider={true}
                  disablePadding
                  secondaryAction={(
                    <>
                      <Tooltip title={t_i18n('Browse the link')}>
                        <IconButton
                          onClick={() => handleOpen(log)}
                          color="primary"
                        >
                        </IconButton>
                      </Tooltip>
                    </>
                  )}
                >
                  <ListItemButton
                    style={{ margin: 0, height: 60 }}
                    onClick={() => handleOpen(log)}
                  >
                    <StixCoreRelationshipHistoryLine
                      key={log.id}
                      nodeRef={log}
                      isRelation={isRelationLog}
                    />
                  </ListItemButton>
                  <HistoryDrawer
                    key={log.id}
                    open={open}
                    onClose={handleClose}
                    title={t_i18n('Relationship log details')}
                    node={selectedLog}
                    isRelation
                  />
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
              ? t_i18n('No relations history about this relationship.')
              : t_i18n('No history about this relationship.')}
          </span>
        </div>
      )}
    </Card>
  );
};

export default StixCoreRelationshipHistoryLines;
