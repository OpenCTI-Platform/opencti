import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { interval } from 'rxjs';
import withStyles from '@mui/styles/withStyles';
import Card from '@mui/material/Card';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid';
import { graphql, createRefetchContainer } from 'react-relay';
import { MultilineChart } from '@mui/icons-material';
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
  constructor(props) {
    super(props);
    this.lastReadOperations = 0;
    this.lastWriteOperations = 0;
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
      const { data } = this.props;
      const { search, indexing } = data.elasticSearchMetrics;
      const currentReadOperations = search.query_total;
      const currentWriteOperations = indexing.index_total + indexing.delete_total;
      this.lastReadOperations = currentReadOperations;
      this.lastWriteOperations = currentWriteOperations;
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    const { classes, t, n, data } = this.props;
    const { consumers, overview } = data.rabbitMQMetrics;
    const { docs, search, indexing } = data.elasticSearchMetrics;
    const currentReadOperations = search.query_total;
    const currentWriteOperations = indexing.index_total + indexing.delete_total;
    let readOperations = null;
    let writeOperations = null;
    if (this.lastReadOperations !== 0) {
      readOperations = (currentReadOperations - this.lastReadOperations) / 5;
      writeOperations = (currentWriteOperations - this.lastWriteOperations) / 5;
    }
    return (
      <Card
        classes={{ root: classes.card }}
        style={{ maxHeight: '100vh', height: '100%' }}
        variant="outlined"
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
            <Grid item={true} xs={2} style={{ height: '25%' }}>
              <div className={classes.metric}>
                <div className={classes.number}>{n(consumers)}</div>
                <div className={classes.title}>{t('Connected workers')}</div>
              </div>
            </Grid>
            <Grid item={true} xs={2} style={{ height: '25%' }}>
              <div className={classes.metric}>
                <div className={classes.number}>
                  {n(pathOr(0, ['queue_totals', 'messages'], overview))}
                </div>
                <div className={classes.title}>{t('Queued bundles')}</div>
              </div>
            </Grid>
            <Grid item={true} xs={2} style={{ height: '25%' }}>
              <div className={classes.metric}>
                <div className={classes.number}>
                  {n(
                    pathOr(
                      0,
                      ['message_stats', 'ack_details', 'rate'],
                      overview,
                    ),
                  )}
                  /s
                </div>
                <div className={classes.title}>{t('Bundles processed')}</div>
              </div>
            </Grid>
            <Grid item={true} xs={2} style={{ height: '25%' }}>
              <div className={classes.metric}>
                <div className={classes.number}>{n(readOperations)}/s</div>
                <div className={classes.title}>{t('Read operations')}</div>
              </div>
            </Grid>
            <Grid item={true} xs={2} style={{ height: '25%' }}>
              <div className={classes.metric}>
                <div className={classes.number}>{n(writeOperations)}/s</div>
                <div className={classes.title}>{t('Write operations')}</div>
              </div>
            </Grid>
            <Grid item={true} xs={2} style={{ height: '25%' }}>
              <div className={classes.metric}>
                <div className={classes.number}>{n(docs.count)}</div>
                <div className={classes.title}>
                  {t('Total number of documents')}
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
  query WorkersStatusQuery {
    ...WorkersStatus_data
  }
`;

const WorkersStatus = createRefetchContainer(
  WorkersStatusComponent,
  {
    data: graphql`
      fragment WorkersStatus_data on Query {
        elasticSearchMetrics {
          docs {
            count
          }
          search {
            query_total
            fetch_total
          }
          indexing {
            index_total
            delete_total
          }
          get {
            total
          }
        }
        rabbitMQMetrics {
          consumers
          overview {
            queue_totals {
              messages
              messages_ready
              messages_unacknowledged
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
