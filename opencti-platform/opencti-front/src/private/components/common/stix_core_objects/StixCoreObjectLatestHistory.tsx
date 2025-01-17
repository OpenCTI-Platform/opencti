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
import { StixCoreObjectHistoryLines_data$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLines_data.graphql';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreObjectHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixCoreObjectHistoryLines';
import { useFormatter } from '../../../../components/i18n';

type StixCoreObjectLatestHistoryProps = {
  stixCoreObjectId: string;
};

const StixCoreObjectLatestHistory = ({ stixCoreObjectId }: StixCoreObjectLatestHistoryProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();

  return (
    <>
      <Typography variant="h4">
        {t_i18n('Most recent history')}
      </Typography>
      <QueryRenderer
        query={stixCoreObjectHistoryLinesQuery}
        variables={{
          filters: {
            mode: 'and',
            filterGroups: [],
            filters: [
              { key: 'context_data.id', values: [stixCoreObjectId] },
              {
                key: 'event_type',
                values: ['mutation', 'create', 'update', 'delete', 'merge'],
              },
            ],
          },
          first: 7,
          orderBy: 'timestamp',
          orderMode: 'desc',
        }}
        render={({ props }: { props: StixCoreObjectHistoryLines_data$data }) => {
          if (props) {
            return (
              <StixCoreObjectHistoryLines
                stixCoreObjectId={stixCoreObjectId}
                data={props}
                isRelationLog={false}
              />
            );
          }
          return (
            <Paper
              sx={{
                marginTop: theme.spacing(1),
                padding: 0,
                borderRadius: 4,
              }}
              variant="outlined"
              className={'paper-for-grid'}
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
                      primary={
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                          style={{ marginBottom: 10 }}
                        />
                      }
                      secondary={
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                        />
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          );
        }}
      />
    </>
  );
};

export default StixCoreObjectLatestHistory;
