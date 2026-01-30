import React from 'react';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Avatar from '@mui/material/Avatar';
import Paper from '@mui/material/Paper';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import StixCoreRelationshipHistoryLines, { stixCoreRelationshipHistoryLinesQuery } from './StixCoreRelationshipHistoryLines';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useAuth from '../../../../utils/hooks/useAuth';

const StixCoreRelationshipLatestHistory = ({ stixCoreRelationshipId }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { tz, locale, unitSystem } = useAuth();
  const paginationOptions = {
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: 'context_data.id', values: [stixCoreRelationshipId] },
        { key: 'event_type', values: ['mutation', 'create', 'update', 'delete', 'merge'] },
      ],
    },
    first: 7,
    orderBy: 'timestamp',
    orderMode: 'desc',
    tz,
    locale: locale,
    unit_system: unitSystem,
  };
  const queryRef = useQueryLoading(
    stixCoreRelationshipHistoryLinesQuery,
    paginationOptions,
  );
  return (
    <div className="break">
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Most recent history')}
      </Typography>
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
            </Paper>
          )}
        >
          <StixCoreRelationshipHistoryLines
            stixCoreRelationshipId={stixCoreRelationshipId}
            queryRef={queryRef}
            isRelationLog={false}
            paginationOptions={paginationOptions}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default StixCoreRelationshipLatestHistory;
