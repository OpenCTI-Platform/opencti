import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import { QueryRenderer as QR } from 'react-relay';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Avatar from '@material-ui/core/Avatar';
import Skeleton from '@material-ui/lab/Skeleton';
import QueryRendererDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import RiskTrackingLines, {
  RiskTrackingLinesQuery,
} from './RiskTrackingLines';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class RiskTracking extends Component {
  render() {
    const { t, classes, risk } = this.props;
    return (
      // <QueryRenderer
      <QR
        environment={QueryRendererDarkLight}
        query={RiskTrackingLinesQuery}
        variables={{ id: '4733f0b3-7eb7-5e68-bd75-b32ecc80254a', count: 200 }}
        render={({ props }) => {
          console.log('RiskTrackingProps', props);
          if (props) {
            return (
              <RiskTrackingLines
                risk={risk}
                data={props}
              />
            );
          }
          return (
            <div style={{ height: '100%' }}>
              <Typography
                variant="h4"
                gutterBottom={true}
                style={{ float: 'left', marginBottom: 15 }}
              >
                {t('Risk Log')}
              </Typography>
              <div className="clearfix" />
              <Paper classes={{ root: classes.paper }} elevation={2}>
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={i}
                      dense={true}
                      divider={true}
                      button={false}
                    >
                      <ListItemIcon>
                        <Avatar classes={{ root: classes.avatarDisabled }}>
                          {i}
                        </Avatar>
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Skeleton
                            animation="wave"
                            variant="rect"
                            width="90%"
                            height={15}
                            style={{ marginBottom: 10 }}
                          />
                        }
                        secondary={
                          <Skeleton
                            animation="wave"
                            variant="rect"
                            width="90%"
                            height={15}
                          />
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </div>
          );
        }}
      />
    );
  }
}

RiskTracking.propTypes = {
  risk: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(RiskTracking);
