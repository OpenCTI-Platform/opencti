import React, { useState } from 'react';
import { graphql, usePreloadedQuery, useRefetchableFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import { useFormatter } from 'src/components/i18n';
import { FIVE_SECONDS } from 'src/utils/Time';
import { useTheme } from '@mui/styles';
import useInterval from 'src/utils/hooks/useInterval';
import HistoryDrawer from '@components/common/drawer/HistoryDrawer';
import ListItem from '@mui/material/ListItem';
import { ListItemButton } from '@mui/material';
import StixCoreRelationshipHistoryLine from '@components/common/stix_core_relationships/StixCoreRelationshipHistoryLine';
import List from '@mui/material/List';

export const stixCoreRelationshipHistoryLinesQuery = graphql`
  query StixCoreRelationshipHistoryLinesQuery(
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
    $tz: String
    $locale: String
    $unit_system: String
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
          context_data(tz: $tz, locale: $locale, unit_system: $unit_system) {
            changes {
              field
            }
          }
          ...StixCoreRelationshipHistoryLine_node @arguments(tz: $tz, locale: $locale, unit_system: $unit_system)
        }
      }
    }
  }
`;

const StixCoreRelationshipHistoryLines = ({ queryRef, isRelationLog, paginationOptions }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const [open, setOpen] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null);
  const queryData = usePreloadedQuery(stixCoreRelationshipHistoryLinesQuery, queryRef);
  const [data, refetch] = useRefetchableFragment(StixCoreRelationshipHistoryLinesFragment, queryData);

  useInterval(() => {
    // Refresh the history every interval
    refetch(paginationOptions, { fetchPolicy: 'store-and-network' });
  }, FIVE_SECONDS);
  const logs = data?.logs.edges ?? [];

  const handleOpen = (logId) => {
    setSelectedLog(logId);
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
    setSelectedLog(undefined);
  };

  return (
    <Paper
      style={{
        height: '100%',
        marginTop: theme.spacing(1),
        borderRadius: 4,
      }}
      className="paper-for-grid"
      variant="outlined"
    >
      <HistoryDrawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Relationship log details')}
        logId={selectedLog}
      />
      {logs.length > 0 ? (
        <List>
          {logs.filter((l) => !!l).map((logEdge) => {
            const log = logEdge.node;
            const hasChanges = (log.context_data?.changes ?? []).length > 0;
            return (
              <React.Fragment key={log.id}>
                <ListItem dense={true} divider={true} disablePadding>
                  <ListItemButton
                    style={{ margin: 0, height: 60, cursor: hasChanges ? 'pointer' : 'default' }}
                    disableRipple={!hasChanges}
                    onClick={() => {
                      if (hasChanges) {
                        handleOpen(log.id);
                      }
                    }}
                  >
                    <StixCoreRelationshipHistoryLine key={log.id} nodeRef={log} isRelation={isRelationLog} />
                  </ListItemButton>
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
    </Paper>
  );
};

export default StixCoreRelationshipHistoryLines;
