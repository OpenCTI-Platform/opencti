import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  propOr,
  pathOr,
  toPairs,
  filter,
  assoc,
  assocPath,
  pipe,
  map,
  sortWith,
  descend,
  path,
} from 'ramda';
import { interval } from 'rxjs';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Card from '@material-ui/core/Card';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import Grid from '@material-ui/core/Grid';
import Avatar from '@material-ui/core/Avatar';
import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableHead from '@material-ui/core/TableHead';
import TableRow from '@material-ui/core/TableRow';
import IconButton from '@material-ui/core/IconButton';
import CardActions from '@material-ui/core/CardActions';
import Collapse from '@material-ui/core/Collapse';
import { createRefetchContainer } from 'react-relay';
import { ExpandMore, Extension, MultilineChart } from '@material-ui/icons';
import NoContent from '../../../components/NoContent';
import inject18n from '../../../components/i18n';
import { FIVE_SECONDS } from '../../../utils/Time';

const interval$ = interval(FIVE_SECONDS);

const styles = theme => ({
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
  confidenceLabel: {
    float: 'right',
    lineHeight: '50px',
    verticalAlign: 'middle',
  },
  confidence: {
    float: 'right',
    margin: '5px 5px 0 20px',
    color: '#ffffff',
    backgroundColor: theme.palette.secondary.main,
  },
  configuration: {
    fontSize: 12,
    padding: '4px 0 0 10px',
    letterSpacing: '3px',
    textTransform: 'uppercase',
  },
  expand: {
    transform: 'rotate(0deg)',
    marginLeft: 'auto',
    transition: theme.transitions.create('transform', {
      duration: theme.transitions.duration.shortest,
    }),
  },
  expandOpen: {
    transform: 'rotate(180deg)',
    marginLeft: 'auto',
    transition: theme.transitions.create('transform', {
      duration: theme.transitions.duration.shortest,
    }),
  },
});

class ConnectorsStatusComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { expanded: {}, messages: {} };
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  handleExpand(key) {
    this.setState({
      expanded: assoc(key, !this.state.expanded[key], this.state.expanded),
    });
  }

  render() {
    const {
      classes, t, n, data,
    } = this.props;
    const sort = sortWith([
      descend(path(['arguments', 'config', 'confidence_level'])),
    ]);
    const overviewMetrics = data.rabbitMQMetrics.overview;
    const queuesMetrics = pipe(
      map(queue => assocPath(
        ['arguments', 'config'],
        JSON.parse(
          Buffer.from(queue.arguments.config, 'base64').toString('ascii'),
        ),
        n,
      )),
      sort,
    )(data.rabbitMQMetrics.queues);
    return (
      <div>
        <Grid container={true} spacing={2} style={{ paddingBottom: 0 }}>
          <Grid item={true} lg={3} xs={5} style={{ paddingBottom: 28 }}>
            <Card
              raised={true}
              classes={{ root: classes.card }}
              style={{ maxHeight: '100vh', height: '100%' }}
            >
              <CardHeader
                avatar={<MultilineChart className={classes.icon} />}
                title={t('Global statistics')}
                style={{ paddingBottom: 0 }}
              />
              <CardContent style={{ paddingTop: 0, height: '100%' }}>
                <Grid
                  container={true}
                  spacing={2}
                  style={{ paddingBottom: 0, height: '100%' }}
                >
                  <Grid item={true} lg={12} xs={12} style={{ height: '25%' }}>
                    <div className={classes.metric}>
                      <div className={classes.number}>
                        {n(overviewMetrics.object_totals.consumers)}
                      </div>
                      <div className={classes.title}>
                        {t('Connected workers')}
                      </div>
                    </div>
                  </Grid>
                  <Grid item={true} lg={12} xs={12} style={{ height: '25%' }}>
                    <div className={classes.metric}>
                      <div className={classes.number}>
                        {n(overviewMetrics.queue_totals.messages_ready)}
                      </div>
                      <div className={classes.title}>
                        {t('Queued messages')}
                      </div>
                    </div>
                  </Grid>
                  <Grid item={true} lg={12} xs={12} style={{ height: '25%' }}>
                    <div className={classes.metric}>
                      <div className={classes.number}>
                        {pathOr(
                          0,
                          ['message_stats', 'ack_details', 'rate'],
                          overviewMetrics,
                        )}
                        /s
                      </div>
                      <div className={classes.title}>
                        {t('Messages processed')}
                      </div>
                    </div>
                  </Grid>
                  <Grid item={true} lg={12} xs={12} style={{ height: '25%' }}>
                    <div className={classes.metric}>
                      <div className={classes.number}>
                        {n(
                          pathOr(0, ['message_stats', 'ack'], overviewMetrics),
                        )}
                      </div>
                      <div className={classes.title}>
                        {t('Total processed messages')}
                      </div>
                    </div>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
          <Grid item={true} lg={9} xs={7}>
            {queuesMetrics.length === 0 ? (
              <NoContent
                message={t('No connectors are enabled on this platform.')}
              />
            ) : (
              queuesMetrics.map((queueMetric) => {
                const { config } = queueMetric.arguments;
                return (
                  <Card
                    raised={true}
                    classes={{ root: classes.card }}
                    key={queueMetric.name}
                  >
                    <CardHeader
                      avatar={<Extension className={classes.icon} />}
                      title={propOr('', 'name', config)}
                      action={
                        <div>
                          <Avatar className={classes.confidence}>
                            {propOr('?', 'confidence_level', config)}
                          </Avatar>
                          <div className={classes.confidenceLabel}>
                            {t('Confidence level')}
                          </div>
                        </div>
                      }
                      style={{ paddingBottom: 0 }}
                    />
                    <CardContent style={{ paddingTop: 0 }}>
                      <Grid
                        container={true}
                        spacing={2}
                        style={{ paddingBottom: 0 }}
                      >
                        <Grid item={true} lg={3} xs={6}>
                          <div className={classes.metric}>
                            <div className={classes.number}>
                              {n(queueMetric.messages_ready)}
                            </div>
                            <div className={classes.title}>
                              {t('Queued messages')}
                            </div>
                          </div>
                        </Grid>
                        <Grid item={true} lg={3} xs={6}>
                          <div className={classes.metric}>
                            <div className={classes.number}>
                              {n(queueMetric.messages_unacknowledged)}
                            </div>
                            <div className={classes.title}>
                              {t('In progress messages')}
                            </div>
                          </div>
                        </Grid>
                        <Grid item={true} lg={3} xs={6}>
                          <div className={classes.metric}>
                            <div className={classes.number}>
                              {pathOr(
                                0,
                                ['message_stats', 'ack_details', 'rate'],
                                queueMetric,
                              )}
                              /s
                            </div>
                            <div className={classes.title}>
                              {t('Messages processed')}
                            </div>
                          </div>
                        </Grid>
                        <Grid item={true} lg={3} xs={6}>
                          <div className={classes.metric}>
                            <div className={classes.number}>
                              {n(
                                pathOr(0, ['message_stats', 'ack'], queueMetric),
                              )}
                            </div>
                            <div className={classes.title}>
                              {t('Total processed messages')}
                            </div>
                          </div>
                        </Grid>
                      </Grid>
                    </CardContent>
                    <CardActions
                      disableSpacing={true}
                      style={{ paddingTop: 0 }}
                    >
                      <div className={classes.configuration}>
                        {t('Configuration')}
                      </div>
                      <IconButton
                        className={
                          this.state.expanded[queueMetric.name]
                            ? classes.expandOpen
                            : classes.expand
                        }
                        onClick={this.handleExpand.bind(this, queueMetric.name)}
                      >
                        <ExpandMore />
                      </IconButton>
                    </CardActions>
                    <Collapse
                      in={this.state.expanded[queueMetric.name]}
                      timeout="auto"
                      unmountOnExit>
                      <CardContent style={{ paddingTop: 0 }}>
                        <Table>
                          <TableHead>
                            <TableRow>
                              <TableCell align="left">{t('Key')}</TableCell>
                              <TableCell align="left">{t('Value')}</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {filter(confElem => confElem[0] !== 'name', toPairs(config)).map(
                              conf => (
                                <TableRow key={conf[0]} hover={true}>
                                  <TableCell align="left">{conf[0]}</TableCell>
                                  <TableCell align="left">
                                    {Array.isArray(conf[1])
                                      ? conf[1].join(',')
                                      : conf[1]}
                                  </TableCell>
                                </TableRow>
                              ),
                            )}
                          </TableBody>
                        </Table>
                      </CardContent>
                    </Collapse>
                  </Card>
                );
              })
            )}
          </Grid>
        </Grid>
      </div>
    );
  }
}

ConnectorsStatusComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  n: PropTypes.func,
  nsdt: PropTypes.func,
  data: PropTypes.object,
};

export const connectorsStatusContentQuery = graphql`
  query ConnectorsStatusContentQuery($prefix: String) {
    ...ConnectorsStatusContent_data @arguments(prefix: $prefix)
  }
`;

const ConnectorsStatusContent = createRefetchContainer(
  ConnectorsStatusComponent,
  {
    data: graphql`
      fragment ConnectorsStatusContent_data on Query
        @argumentDefinitions(prefix: { type: "String" }) {
        rabbitMQMetrics(prefix: $prefix) {
          overview {
            queue_totals {
              messages
              messages_ready
            }
            object_totals {
              consumers
              queues
            }
            message_stats {
              ack
              ack_details {
                rate
              }
            }
            node
          }
          queues {
            name
            messages
            messages_ready
            messages_unacknowledged
            consumers
            idle_since
            arguments {
              config
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
  connectorsStatusContentQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(ConnectorsStatusContent);
