import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { interval } from 'rxjs';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import { createRefetchContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import withTheme from '@mui/styles/withTheme';
import Paper from '@mui/material/Paper';
import { FIVE_SECONDS } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  card: {
    borderRadius: 4,
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
      const currentReadOperations = Number(search.query_total);
      const currentWriteOperations = Number(indexing.index_total) + Number(indexing.delete_total);
      this.lastReadOperations = currentReadOperations;
      this.lastWriteOperations = currentWriteOperations;
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    const { classes, t, n, data, theme } = this.props;
    const { consumers, overview } = data.rabbitMQMetrics;
    const { docs, search, indexing } = data.elasticSearchMetrics;
    const currentReadOperations = Number(search.query_total);
    const currentWriteOperations = Number(indexing.index_total) + Number(indexing.delete_total);
    let readOperations = null;
    let writeOperations = null;
    if (this.lastReadOperations !== 0) {
      readOperations = (currentReadOperations - this.lastReadOperations) / 5;
    }
    if (this.lastWriteOperations !== 0) {
      writeOperations = (currentWriteOperations - this.lastWriteOperations) / 5;
    }
    return (
      <Grid
        container={true}
        spacing={3}
        style={{ paddingBottom: 0, height: '100%' }}
      >
        <Grid item xs={2} style={{ height: '25%' }}>
          <Paper
            variant="outlined"
            style={{
              display: 'flex',
              padding: theme.spacing(2),
              justifyContent: 'center',
              alignItems: 'center',
              flexDirection: 'column',
            }}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'}>
              {t('Connected workers')}
            </Typography>
            <div className={classes.number}>{n(consumers)}</div>
          </Paper>
        </Grid>
        <Grid item xs={2} style={{ height: '25%' }}>
          <Paper
            variant="outlined"
            style={{
              display: 'flex',
              padding: theme.spacing(2),
              justifyContent: 'center',
              alignItems: 'center',
              flexDirection: 'column',
            }}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'}>
              {t('Queued bundles')}
            </Typography>
            <div className={classes.number}>
              {n(pathOr(0, ['queue_totals', 'messages'], overview))}
            </div>
          </Paper>
        </Grid>
        <Grid item xs={2} style={{ height: '25%' }}>
          <Paper
            variant="outlined"
            style={{
              display: 'flex',
              padding: theme.spacing(2),
              justifyContent: 'center',
              alignItems: 'center',
              flexDirection: 'column',
            }}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'}>
              {t('Bundles processed')}
            </Typography>
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
          </Paper>
        </Grid>
        <Grid item xs={2} style={{ height: '25%' }}>
          <Paper
            variant="outlined"
            style={{
              display: 'flex',
              padding: theme.spacing(2),
              justifyContent: 'center',
              alignItems: 'center',
              flexDirection: 'column',
            }}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'}>
              {t('Read operations')}
            </Typography>
            <div className={classes.number}>{n(readOperations)}/s</div>
          </Paper>
        </Grid>
        <Grid item xs={2} style={{ height: '25%' }}>
          <Paper
            variant="outlined"
            style={{
              display: 'flex',
              padding: theme.spacing(2),
              justifyContent: 'center',
              alignItems: 'center',
              flexDirection: 'column',
            }}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'}>
              {t('Write operations')}
            </Typography>
            <div className={classes.number}>{n(writeOperations)}/s</div>
          </Paper>
        </Grid>
        <Grid item xs={2} style={{ height: '25%' }}>
          <Paper
            variant="outlined"
            style={{
              display: 'flex',
              padding: theme.spacing(2),
              justifyContent: 'center',
              alignItems: 'center',
              flexDirection: 'column',
              overflow: 'hidden',
            }}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'} style={{ textWrap: 'nowrap', textOverflow: 'ellipsis' }}>
              {t('Total number of documents')}
            </Typography>
            <div className={classes.number}>{n(docs.count)}</div>
          </Paper>
        </Grid>
      </Grid>
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

export default compose(inject18n, withStyles(styles), withTheme)(WorkersStatus);
