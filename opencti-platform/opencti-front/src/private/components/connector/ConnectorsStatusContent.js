import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, propOr, pathOr, toPairs, filter, assoc,
} from 'ramda';
import { interval } from 'rxjs';
import graphql from 'babel-plugin-relay/macro';
import SwipeableViews from 'react-swipeable-views';
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
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import { createRefetchContainer } from 'react-relay';
import NoContent from '../../../components/NoContent';
import inject18n from '../../../components/i18n';
import { FIVE_SECONDS } from '../../../utils/Time';

const interval$ = interval(FIVE_SECONDS);

const styles = theme => ({
  card: {
    width: '100%',
    minHeight: '100%',
    marginBottom: 20,
    borderRadius: 6,
  },
  tabContent: {
    width: '100%',
    overflow: 'hidden',
  },
  metric: {
    margin: '0 auto',
    textAlign: 'center',
    padding: '20px 0 0 0',
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
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
});

class ConnectorsStatusComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { tabs: {}, messages: {} };
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  switchTab(key, event, value) {
    this.setState({ tabs: assoc(key, value, this.state.tabs) });
  }

  render() {
    const {
      classes, t, nsdt, data,
    } = this.props;
    const { queuesMetrics } = data;
    return (
      <div>
        <Grid container={true} spacing={2}>
          {queuesMetrics.length === 0 ? (
            <NoContent
              message={t('No connectors are enabled on this platform.')}
            />
          ) : (
            queuesMetrics.map((queueMetric) => {
              const config = JSON.parse(
                Buffer.from(queueMetric.arguments.config, 'base64').toString(
                  'ascii',
                ),
              );
              return (
                <Grid item={true} lg={6} xs={12} key={queueMetric.name}>
                  <Card raised={true} classes={{ root: classes.card }}>
                    <CardHeader
                      avatar={
                        <Avatar aria-label="Recipe" className={classes.avatar}>
                          {propOr(' ', 'name', config).charAt(0)}
                        </Avatar>
                      }
                      title={propOr('', 'name', config)}
                    />
                    <CardContent style={{ paddingTop: 0 }}>
                      <Tabs
                        value={propOr(0, queueMetric.name, this.state.tabs)}
                        onChange={this.switchTab.bind(this, queueMetric.name)}
                        indicatorColor="primary"
                        textColor="primary"
                        variant="fullWidth"
                      >
                        <Tab label={t('Metrics')} />
                        <Tab label={t('Configuration')} />
                      </Tabs>
                      <SwipeableViews
                        axis="x"
                        index={propOr(0, queueMetric.name, this.state.tabs)}
                      >
                        <div className={classes.tabContent}>
                          <Grid container={true} spacing={2}>
                            <Grid item={true} lg={6} xs={12}>
                              <div className={classes.metric}>
                                <div className={classes.number}>
                                  {queueMetric.messages_ready}
                                </div>
                                <div className={classes.title}>
                                  {t('Queued messages')}
                                </div>
                              </div>
                            </Grid>
                            <Grid item={true} lg={6} xs={12}>
                              <div className={classes.metric}>
                                <div className={classes.number}>
                                  {queueMetric.messages_unacknowledged}
                                </div>
                                <div className={classes.title}>
                                  {t('In progress messages')}
                                </div>
                              </div>
                            </Grid>
                            <Grid item={true} lg={6} xs={12}>
                              <div className={classes.metric}>
                                <div className={classes.number}>
                                  {pathOr(
                                    0,
                                    [
                                      'deliver_details',
                                      'message_stats',
                                      'rate',
                                    ],
                                    queueMetric,
                                  )}
                                  /s
                                </div>
                                <div className={classes.title}>
                                  {t('Messages processed')}
                                </div>
                              </div>
                            </Grid>
                            <Grid item={true} lg={6} xs={12}>
                              <div className={classes.metric}>
                                <div className={classes.date}>
                                  {nsdt(queueMetric.idle_since)}
                                </div>
                                <div className={classes.title}>
                                  {t('Last processed message')}
                                </div>
                              </div>
                            </Grid>
                          </Grid>
                        </div>
                        <div className={classes.tabContent}>
                          <Table>
                            <TableHead>
                              <TableRow>
                                <TableCell align="left">{t('Key')}</TableCell>
                                <TableCell align="left">{t('Value')}</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {filter(
                                n => n[0] !== 'name',
                                toPairs(config),
                              ).map(conf => (
                                <TableRow key={conf[0]} hover={true}>
                                  <TableCell align="left">{conf[0]}</TableCell>
                                  <TableCell align="left">
                                    {Array.isArray(conf[1])
                                      ? conf[1].join(',')
                                      : conf[1]}
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      </SwipeableViews>
                    </CardContent>
                  </Card>
                </Grid>
              );
            })
          )}
        </Grid>
      </div>
    );
  }
}

ConnectorsStatusComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
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
        queuesMetrics(prefix: $prefix) {
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
            deliver_details {
              rate
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
