import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Avatar from '@mui/material/Avatar';
import Paper from '@mui/material/Paper';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreObjectHistoryLines, {
  stixCoreObjectHistoryLinesQuery,
} from './StixCoreObjectHistoryLines';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  paperHistory: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 15,
    borderRadius: 6,
  },
});

class StixCoreObjectLatestHistory extends Component {
  render() {
    const { t, stixCoreObjectId, classes } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Most recent history')}
        </Typography>
        <QueryRenderer
          query={stixCoreObjectHistoryLinesQuery}
          variables={{
            filters: [
              { key: 'entity_id', values: [stixCoreObjectId] },
              {
                key: 'event_type',
                values: ['create', 'update', 'merge'],
              },
            ],
            first: 7,
            orderBy: 'timestamp',
            orderMode: 'desc',
          }}
          render={({ props }) => {
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
                classes={{ root: classes.paperHistory }}
                variant="outlined"
              >
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={i}
                      dense={true}
                      divider={true}
                      button={false}
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
      </div>
    );
  }
}

StixCoreObjectLatestHistory.propTypes = {
  t: PropTypes.func,
  stixCoreObjectId: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectLatestHistory);
