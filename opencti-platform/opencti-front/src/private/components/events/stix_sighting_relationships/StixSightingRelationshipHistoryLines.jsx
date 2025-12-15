import React, { useState } from 'react';
import { graphql, usePreloadedQuery, useRefetchableFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import StixCoreObjectHistoryLine from '../../common/stix_core_objects/StixCoreObjectHistoryLine';
import { useTheme } from '@mui/styles';
import { useFormatter } from 'src/components/i18n';
import useInterval from 'src/utils/hooks/useInterval';
import { FIVE_SECONDS } from 'src/utils/Time';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import ListItem from '@mui/material/ListItem';
import { ListItemButton } from '@mui/material';
import HistoryDrawer from '@components/common/drawer/HistoryDrawer';

export const stixCoreObjectHistoryLinesQuery = graphql`
  query StixSightingRelationshipHistoryLinesQuery(
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    ...StixSightingRelationshipHistoryLines_data
  }
`;

const StixSightingRelationshipHistoryFragment = graphql`
  fragment StixSightingRelationshipHistoryLines_data on Query
  @refetchable(queryName: "StixSightingRelationshipHistoryRefetchQuery")
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
          ...StixCoreObjectHistoryLine_node
        }
      }
    }
  }
`;

const StixSightingRelationshipHistoryLines = ({ queryRef, isRelationLog, paginationOptions }) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [selectedLog, setSelectedLog] = useState(undefined);
  const queryData = usePreloadedQuery(stixCoreObjectHistoryLinesQuery, queryRef);
  const [data, refetch] = useRefetchableFragment(StixSightingRelationshipHistoryFragment, queryData);
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
    <Paper
      style={{
        marginTop: theme.spacing(1),
        padding: '0 15px',
        borderRadius: 4,
      }}
      className="paper-for-grid"
      variant="outlined"
    >
      {logs.length > 0 ? (
        logs.map((logEdge) => {
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
                  <StixCoreObjectHistoryLine
                    key={log.id}
                    node={log}
                    isRelation={isRelationLog}
                  />
                </ListItemButton>
                <HistoryDrawer
                  key={log.id}
                  open={open}
                  onClose={handleClose}
                  title={t_i18n('Sightings log details')}
                  node={selectedLog}
                />
              </ListItem>
            </React.Fragment>
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
              ? t_i18n('No relations history about this relationship.')
              : t_i18n('No history about this relationship.')}
          </span>
        </div>
      )}
    </Paper>
  );
};

export default StixSightingRelationshipHistoryLines;
