import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { interval } from 'rxjs';
import Grid from '@mui/material/Grid';
import { createRefetchContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import Card from '@common/card/Card';
import { FIVE_SECONDS } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import { useTheme } from '@mui/material';

const interval$ = interval(FIVE_SECONDS);

const MetricCard = ({ title, value }) => {
  const theme = useTheme();

  const paperStyle = {
    display: 'flex',
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
    <Card>
      <div style={paperStyle}>
        <Typography variant="h5">{title}</Typography>
        <div style={numberStyle}>{value}</div>
      </div>
    </Card>
  );
};

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

  safeValue = (value, formatter, suffix = '') => {
    return value != null ? `${formatter(value)}${suffix}` : '-';
  };

  render() {
    const { t, n, data } = this.props;
    const { consumers, overview } = data?.rabbitMQMetrics || {};
    const { docs, search, indexing } = data?.elasticSearchMetrics || {};

    const currentReadOperations = search ? Number(search.query_total) : null;
    const currentWriteOperations = search && indexing
      ? Number(indexing.index_total) + Number(indexing.delete_total)
      : null;

    let readOperations = null;
    let writeOperations = null;
    if (this.lastReadOperations !== 0 && currentReadOperations != null) {
      readOperations = (currentReadOperations - this.lastReadOperations) / 5;
    }
    if (this.lastWriteOperations !== 0 && currentWriteOperations != null) {
      writeOperations = (currentWriteOperations - this.lastWriteOperations) / 5;
    }

    return (
      <Grid container={true} spacing={3}>
        <Grid item xs={2}>
          <MetricCard
            title={t('Connected workers')}
            value={this.safeValue(consumers, n)}
          />
        </Grid>
        <Grid item xs={2}>
          <MetricCard
            title={t('Queued bundles')}
            value={this.safeValue(overview ? pathOr(0, ['queue_totals', 'messages'], overview) : null, n)}
          />
        </Grid>
        <Grid item xs={2}>
          <MetricCard
            title={t('Bundles processed')}
            value={this.safeValue(overview ? pathOr(0, ['message_stats', 'ack_details', 'rate'], overview) : null, n, '/s')}
          />
        </Grid>
        <Grid item xs={2}>
          <MetricCard
            title={t('Read operations')}
            value={this.safeValue(readOperations, n, '/s')}
          />
        </Grid>
        <Grid item xs={2}>
          <MetricCard
            title={t('Write operations')}
            value={this.safeValue(writeOperations, n, '/s')}
          />
        </Grid>
        <Grid item xs={2}>
          <MetricCard
            title={t('Total number of documents')}
            value={this.safeValue(docs?.count, n)}
          />
        </Grid>
      </Grid>
    );
  }
}

WorkersStatusComponent.propTypes = {
  classes: PropTypes.object,
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

export default compose(inject18n)(WorkersStatus);
