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
import ListItem from '@mui/material/ListItem';
import { ListItemButton } from '@mui/material';
import HistoryDrawer from '@components/common/drawer/HistoryDrawer';
import useInterval from '../../../../utils/hooks/useInterval';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../components/Theme';

export const stixCoreObjectHistoryLinesQuery = graphql`
  query StixCoreObjectHistoryLinesQuery(
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
    $tz: String
    $locale: String
    $unit_system: String
  ) {
    ...StixCoreObjectHistoryLines_data
  }
`;

export const StixCoreObjectHistoryLinesFragment = graphql`
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
          context_data(tz: $tz, locale: $locale, unit_system: $unit_system) {
            changes {
              field
            }
          }
          ...StixCoreObjectHistoryLine_node @arguments(tz: $tz, locale: $locale, unit_system: $unit_system)
        }
      }
    }
  }
`;

interface StixCoreObjectHistoryLinesProps {
  queryRef: PreloadedQuery<StixCoreObjectHistoryLinesQuery>;
  isRelationLog: boolean;
  paginationOptions: StixCoreObjectHistoryLinesQuery$variables;
}

const StixCoreObjectHistoryLines: FunctionComponent<StixCoreObjectHistoryLinesProps> = ({
  queryRef,
  isRelationLog,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [open, setOpen] = useState(false);
  const [selectedLog, setSelectedLog] = useState<string | undefined>(undefined);
  const queryData = usePreloadedQuery(stixCoreObjectHistoryLinesQuery, queryRef);
  const [data, refetch] = useRefetchableFragment<StixCoreObjectHistoryLinesQuery, StixCoreObjectHistoryLines_data$key>(
    StixCoreObjectHistoryLinesFragment,
    queryData,
  );
  useInterval(() => {
    // Refresh the history every interval
    refetch(paginationOptions, { fetchPolicy: 'store-and-network' });
  }, FIVE_SECONDS);
  const logs = data?.logs?.edges ?? [];
  const handleOpen = (id: string) => {
    setSelectedLog(id);
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
    setSelectedLog(undefined);
  };

  return (
    <Paper
      style={{
        borderRadius: 4,
        marginTop: theme.spacing(1),
      }}
      className="paper-for-grid"
      variant="outlined"
    >
      <HistoryDrawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Knowledge log details')}
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
                    <StixCoreObjectHistoryLine key={log.id} node={log} isRelation={isRelationLog} />
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
              ? t_i18n('No relations history about this entity.')
              : t_i18n('No history about this entity.')}
          </span>
        </div>
      )}
    </Paper>
  );
};

export default StixCoreObjectHistoryLines;
