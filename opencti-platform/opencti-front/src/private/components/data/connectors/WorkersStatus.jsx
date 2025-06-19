import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { interval } from 'rxjs';
import Grid from '@mui/material/Grid';
import { createRefetchContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import withTheme from '@mui/styles/withTheme';
import Paper from '@mui/material/Paper';
import { FIVE_SECONDS } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';

const interval$ = interval(FIVE_SECONDS);

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
    const { t, n, data, theme } = this.props;
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

    const paperStyle = {
      display: 'flex',
      padding: theme.spacing(2),
      justifyContent: 'space-between',
      alignItems: 'center',
      flexDirection: 'column',
      height: '100%',
    };
    const numberStyle = {
      color: theme.palette.primary.main,
      fontSize: 32,
      lineHeight: '60px',
      verticalAlign: 'middle',
    };

    return (
      <Grid
        container={true}
        spacing={3}
      >
        <Grid item xs={2}>
          <Paper
            variant="outlined"
            style={paperStyle}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'}>
              {t('Connected workers')}
            </Typography>
            <div style={numberStyle}>{n(consumers)}</div>
          </Paper>
        </Grid>
        <Grid item xs={2} >
          <Paper
            variant="outlined"
            style={paperStyle}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'}>
              {t('Queued bundles')}
            </Typography>
            <div style={numberStyle}>
              {n(pathOr(0, ['queue_totals', 'messages'], overview))}
            </div>
          </Paper>
        </Grid>
        <Grid item xs={2} >
          <Paper
            variant="outlined"
            style={paperStyle}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'}>
              {t('Bundles processed')}
            </Typography>
            <div style={numberStyle}>
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
        <Grid item xs={2} >
          <Paper
            variant="outlined"
            style={paperStyle}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'}>
              {t('Read operations')}
            </Typography>
            <div style={numberStyle}>{n(readOperations)}/s</div>
          </Paper>
        </Grid>
        <Grid item xs={2} >
          <Paper
            variant="outlined"
            style={paperStyle}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'}>
              {t('Write operations')}
            </Typography>
            <div style={numberStyle}>{n(writeOperations)}/s</div>
          </Paper>
        </Grid>
        <Grid item xs={2} >
          <Paper
            variant="outlined"
            style={paperStyle}
            className={'paper-for-grid'}
          >
            <Typography variant={'h5'} >
              {t('Total number of documents')}
            </Typography>
            <div style={numberStyle}>{n(docs.count)}</div>
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

export default compose(inject18n, withTheme)(WorkersStatus);
