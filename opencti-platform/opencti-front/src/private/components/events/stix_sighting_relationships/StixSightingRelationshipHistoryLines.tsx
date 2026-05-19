import React, { useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useRefetchableFragment } from 'react-relay';
import StixCoreObjectHistoryLine from '../../common/stix_core_objects/StixCoreObjectHistoryLine';
import { useFormatter } from 'src/components/i18n';
import useInterval from 'src/utils/hooks/useInterval';
import { FIVE_SECONDS } from 'src/utils/Time';
import ListItem from '@mui/material/ListItem';
import { ListItemButton } from '@mui/material';
import HistoryDrawer from '@components/common/drawer/HistoryDrawer';
import Card from '@common/card/Card';
import { StixSightingRelationshipHistoryLinesQuery, StixSightingRelationshipHistoryLinesQuery$variables } from './__generated__/StixSightingRelationshipHistoryLinesQuery.graphql';
import { StixSightingRelationshipHistoryLines_data$key } from './__generated__/StixSightingRelationshipHistoryLines_data.graphql';
import { StixSightingRelationshipHistoryRefetchQuery } from './__generated__/StixSightingRelationshipHistoryRefetchQuery.graphql';

export const stixCoreObjectHistoryLinesQuery = graphql`
  query StixSightingRelationshipHistoryLinesQuery(
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
    $tz: String
    $locale: String
    $unit_system: String
  ) {
    ...StixSightingRelationshipHistoryLines_data
  }
`;

const StixSightingRelationshipHistoryFragment = graphql`
  fragment StixSightingRelationshipHistoryLines_data on Query
  @refetchable(queryName: "StixSightingRelationshipHistoryRefetchQuery") {
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

interface StixSightingRelationshipHistoryLinesProps {
  queryRef: PreloadedQuery<StixSightingRelationshipHistoryLinesQuery>;
  isRelationLog: boolean;
  paginationOptions: StixSightingRelationshipHistoryLinesQuery$variables;
}

const StixSightingRelationshipHistoryLines = ({ queryRef, isRelationLog, paginationOptions }: StixSightingRelationshipHistoryLinesProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [selectedLog, setSelectedLog] = useState<string | undefined>(undefined);
  const queryData = usePreloadedQuery(stixCoreObjectHistoryLinesQuery, queryRef);
  const [data, refetch] = useRefetchableFragment<StixSightingRelationshipHistoryRefetchQuery, StixSightingRelationshipHistoryLines_data$key>(
    StixSightingRelationshipHistoryFragment,
    queryData,
  );

  useInterval(() => {
    // Refresh the history every interval
    refetch(paginationOptions, { fetchPolicy: 'store-and-network' });
  }, FIVE_SECONDS);
  const logs = data?.logs?.edges ?? [];

  const handleOpen = (logId: string) => {
    setSelectedLog(logId);
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
    setSelectedLog(undefined);
  };

  return (
    <Card title={t_i18n('Most recent history')}>
      <HistoryDrawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Sightings log details')}
        logId={selectedLog}
      />
      {logs.length > 0 ? (
        logs.filter((l) => !!l).map((logEdge) => {
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
    </Card>
  );
};

export default StixSightingRelationshipHistoryLines;
