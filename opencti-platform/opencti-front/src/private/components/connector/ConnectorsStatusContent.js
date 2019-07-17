import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, propOr, pathOr, toPairs, filter, assoc,
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
import { ExpandMore } from '@material-ui/icons';
import NoContent from '../../../components/NoContent';
import inject18n from '../../../components/i18n';
import { FIVE_SECONDS } from '../../../utils/Time';

const interval$ = interval(FIVE_SECONDS);

const styles = theme => ({
  card: {
    width: '60%',
    margin: '0 auto',
    marginBottom: 20,
    borderRadius: 6,
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
      classes, t, nsdt, data,
    } = this.props;
    const { queuesMetrics } = data;
    return (
      <div>
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
              <Card
                raised={true}
                classes={{ root: classes.card }}
                key={queueMetric.name}
              >
                <CardHeader
                  avatar={
                    <Avatar aria-label="Recipe" className={classes.avatar}>
                      {propOr(' ', 'name', config).charAt(0)}
                    </Avatar>
                  }
                  title={propOr('', 'name', config)}
                  style={{ paddingBottom: 0 }}
                />
                <CardContent style={{ paddingTop: 0 }}>
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
                            ['deliver_details', 'message_stats', 'rate'],
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
                </CardContent>
                <CardActions disableSpacing>
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
                  unmountOnExit
                >
                  <CardContent style={{ paddingTop: 0 }}>
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell align="left">{t('Key')}</TableCell>
                          <TableCell align="left">{t('Value')}</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {filter(n => n[0] !== 'name', toPairs(config)).map(
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
