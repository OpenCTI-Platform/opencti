import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, indexBy, prop } from 'ramda';
import { interval } from 'rxjs';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Card from '@material-ui/core/Card';
import CardContent from '@material-ui/core/CardContent';
import Grid from '@material-ui/core/Grid';
import { createRefetchContainer } from 'react-relay';
import { DatabaseImport } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import { FIVE_SECONDS } from '../../../utils/Time';

const interval$ = interval(FIVE_SECONDS);

const styles = theme => ({
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 6,
    position: 'relative',
  },
  paper: {
    minHeight: '100%',
    margin: '10px 0 20px 0',
    padding: 0,
    borderRadius: 6,
  },
  item: {
    height: 60,
    minHeight: 60,
    maxHeight: 60,
    transition: 'background-color 0.1s ease',
    paddingRight: 0,
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  itemIconSecondary: {
    marginRight: 0,
    color: theme.palette.secondary.main,
  },
  number: {
    float: 'left',
    color: theme.palette.primary.main,
    fontSize: 40,
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
  },
  icon: {
    position: 'absolute',
    top: 30,
    right: 20,
  },
});

class ConnectorsStatusComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  render() {
    const { classes, t, queuesStats } = this.props;
    const queues = indexBy(prop('name'), queuesStats.connectorsStats.queues);
    return (
      <div>
        <Grid container={true} spacing={2}>
          <Grid item={true} lg={3} xs={6}>
            <Card
              raised={true}
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <CardContent>
                <div className={classes.number}>{queues['opencti-import'].messages_ready}</div>
                <div className="clearfix" />
                <div className={classes.title}>{t('Total pending inserts')}</div>
                <div className={classes.icon}>
                  <DatabaseImport color="inherit" fontSize="large" />
                </div>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </div>
    );
  }
}

ConnectorsStatusComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  queuesStats: PropTypes.object,
};

export const connectorsStatusContentQuery = graphql`
  query ConnectorsStatusContentQuery {
    ...ConnectorsStatusContent_queuesStats
  }
`;

const ConnectorsStatusContent = createRefetchContainer(
  ConnectorsStatusComponent,
  {
    queuesStats: graphql`
      fragment ConnectorsStatusContent_queuesStats on Query {
        connectorsStats {
          queues {
            name
            messages
            messages_ready
            messages_unacknowledged
            consumers
            message_stats {
              deliver_details {
                rate
              }
            }
          }
        }
      }
    `,
  },
  connectorsStatusContentQuery,
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ConnectorsStatusContent);
