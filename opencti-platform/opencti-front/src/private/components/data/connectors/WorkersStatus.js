import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { interval } from 'rxjs';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Card from '@material-ui/core/Card';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import Grid from '@material-ui/core/Grid';
import { createRefetchContainer } from 'react-relay';
import { MultilineChart } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  card: {
    marginBottom: 20,
    borderRadius: 6,
  },
  metric: {
    margin: '0 auto',
    textAlign: 'center',
  },
  number: {
    color: theme.palette.primary.main,
    fontSize: 40,
    lineHeight: '60px',
    verticalAlign: 'middle',
  },
  date: {
    color: theme.palette.primary.main,
    fontSize: 20,
    lineHeight: '60px',
    verticalAlign: 'middle',
  },
  title: {
    textTransform: 'uppercase',
    fontSize: 12,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

class WorkersStatusComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    const {
      classes, t, n, data,
    } = this.props;
    const { consumers, overview } = data.rabbitMQMetrics;
    return (
      <Card
        classes={{ root: classes.card }}
        style={{ maxHeight: '100vh', height: '100%' }}
      >
        <CardHeader
          avatar={<MultilineChart className={classes.icon} />}
          title={t('Workers statistics')}
          style={{ paddingBottom: 0 }}
        />
        <CardContent style={{ paddingTop: 0, height: '100%' }}>
          <Grid
            container={true}
            spacing={3}
            style={{ paddingBottom: 0, height: '100%' }}
          >
            <Grid item={true} xs={3} style={{ height: '25%' }}>
              <div className={classes.metric}>
                <div className={classes.number}>{n(consumers)}</div>
                <div className={classes.title}>{t('Connected workers')}</div>
              </div>
            </Grid>
            <Grid item={true} xs={3} style={{ height: '25%' }}>
              <div className={classes.metric}>
                <div className={classes.number}>
                  {n(overview.queue_totals.messages_ready)}
                </div>
                <div className={classes.title}>{t('Queued messages')}</div>
              </div>
            </Grid>
            <Grid item={true} xs={3} style={{ height: '25%' }}>
              <div className={classes.metric}>
                <div className={classes.number}>
                  {pathOr(
                    0,
                    ['message_stats', 'ack_details', 'rate'],
                    overview,
                  )}
                  /s
                </div>
                <div className={classes.title}>{t('Messages processed')}</div>
              </div>
            </Grid>
            <Grid item={true} xs={3} style={{ height: '25%' }}>
              <div className={classes.metric}>
                <div className={classes.number}>
                  {n(pathOr(0, ['message_stats', 'ack'], overview))}
                </div>
                <div className={classes.title}>
                  {t('Total processed messages')}
                </div>
              </div>
            </Grid>
          </Grid>
        </CardContent>
      </Card>
    );
  }
}

WorkersStatusComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  n: PropTypes.func,
  nsdt: PropTypes.func,
  data: PropTypes.object,
};

export const workersStatusQuery = graphql`
  query WorkersStatusQuery($prefix: String) {
    ...WorkersStatus_data @arguments(prefix: $prefix)
  }
`;

const WorkersStatus = createRefetchContainer(
  WorkersStatusComponent,
  {
    data: graphql`
      fragment WorkersStatus_data on Query
        @argumentDefinitions(prefix: { type: "String" }) {
        rabbitMQMetrics(prefix: $prefix) {
          consumers
          overview {
            queue_totals {
              messages_ready
            }
            message_stats {
              ack
              ack_details {
                rate
              }
            }
          }
        }
      }
    `,
  },
  workersStatusQuery,
);

export default compose(inject18n, withStyles(styles))(WorkersStatus);
