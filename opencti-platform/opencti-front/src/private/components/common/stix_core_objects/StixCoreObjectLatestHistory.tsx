import React from 'react';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Avatar from '@mui/material/Avatar';
import Paper from '@mui/material/Paper';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import {
  StixCoreObjectHistoryLinesQuery,
  StixCoreObjectHistoryLinesQuery$variables,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLinesQuery.graphql';
import StixCoreObjectHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixCoreObjectHistoryLines';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useAuth from '../../../../utils/hooks/useAuth';
import Card from '../../../../components/common/card/Card';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';

type StixCoreObjectLatestHistoryProps = {
  stixCoreObjectId: string;
};

const StixCoreObjectLatestHistory = ({ stixCoreObjectId }: StixCoreObjectLatestHistoryProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { tz, locale, unitSystem } = useAuth();

  const paginationOptions: StixCoreObjectHistoryLinesQuery$variables = {
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: ['context_data.id'], values: [stixCoreObjectId] },
        {
          key: ['event_type'],
          values: ['mutation', 'create', 'update', 'delete', 'merge'],
        },
      ],
    },
    first: 7,
    orderBy: 'timestamp',
    orderMode: 'desc',
    tz,
    locale: locale,
    unit_system: unitSystem,
  };

  const queryRef = useQueryLoading<StixCoreObjectHistoryLinesQuery>(
    stixCoreObjectHistoryLinesQuery,
    paginationOptions,
  );

  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={(
            <Paper
              sx={{
                marginTop: theme.spacing(1),
                padding: 0,
                borderRadius: 4,
              }}
              variant="outlined"
              className="paper-for-grid"
            >
              <Card title={t_i18n('Most recent history')} padding="horizontal">
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={`latest_history_skel_${i}`}
                      dense
                      divider
                    >
                      <ListItemIcon>
                        <Avatar>{i}</Avatar>
                      </ListItemIcon>
                      <ListItemText
                        primary={(
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                            style={{ marginBottom: 10 }}
                          />
                        )}
                        secondary={(
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                          />
                        )}
                      />
                    </ListItem>
                  ))}
                </List>
              </Card>
            </Paper>
          )}
        >
          <StixCoreObjectHistoryLines
            title={t_i18n('Most recent history')}
            queryRef={queryRef}
            isRelationLog={false}
            paginationOptions={paginationOptions}
          />
        </React.Suspense>
      )
      }
    </>
  );
};

export default StixCoreObjectLatestHistory;
