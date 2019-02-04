import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { compose, head, pathOr } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Card from '@material-ui/core/Card';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import CardContent from '@material-ui/core/CardContent';
import {
  ArrowUpward, Assignment, Layers, DeviceHub, Description,
} from '@material-ui/icons';
import {
  Database,
} from 'mdi-material-ui';
import BarChart from 'recharts/lib/chart/BarChart';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import Bar from 'recharts/lib/cartesian/Bar';
import XAxis from 'recharts/lib/cartesian/XAxis';
import YAxis from 'recharts/lib/cartesian/YAxis';
import Tooltip from 'recharts/lib/component/Tooltip';
import { QueryRenderer } from '../../relay/environment';
import truncate from '../../utils/String';
import { yearsAgo, now } from '../../utils/Time';
import { resolveLink } from '../../utils/Entity';
import Theme from '../../components/Theme';
import inject18n from '../../components/i18n';
import ItemIcon from '../../components/ItemIcon';
import ItemMarking from '../../components/ItemMarking';

const styles = theme => ({
  card: {
    width: '100%',
    marginBottom: 20,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
    position: 'relative',
  },
  paper: {
    minHeight: '100%',
    margin: '10px 0 20px 0',
    padding: 0,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
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
    marginRight: 0,
    color: theme.palette.primary.main,
  },
  number: {
    float: 'left',
    color: theme.palette.primary.main,
    fontSize: 40,
  },
  diff: {
    float: 'left',
    margin: '13px 0 0 10px',
    fontSize: 13,
  },
  diffIcon: {
    float: 'left',
    color: '#4caf50',
  },
  diffNumber: {
    marginTop: 6,
    float: 'left',
    color: '#4caf50',
  },
  diffDescription: {
    margin: '6px 0 0 10px',
    float: 'left',
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
  graphContainer: {
    width: '100%',
    margin: '20px 0 0 -30px',
  },
});

const inlineStyles = {
  itemDate: {
    fontSize: 11,
    width: 80,
    minWidth: 80,
    maxWidth: 80,
    marginRight: 24,
    textAlign: 'right',
    color: '#ffffff',
  },
};

const dashboardStixDomainEntitiesTimeSeriesQuery = graphql`
    query DashboardStixDomainEntitiesTimeSeriesQuery($field: String!, $operation: StatsOperation!, $startDate: DateTime!, $endDate: DateTime!, $interval: String!) {
        stixDomainEntitiesTimeSeries(field: $field, operation: $operation, startDate: $startDate, endDate: $endDate, interval: $interval) {
            date,
            value
        }
    }
`;

const dashboardLastReportsQuery = graphql`
    query DashboardLastReportsQuery($reportClass: String, $first: Int, $orderBy: ReportsOrdering, $orderMode: OrderingMode) {
        reports(reportClass: $reportClass, first: $first, orderBy: $orderBy, orderMode: $orderMode) {
            edges {
                node {
                    id
                    name
                    description
                    published
                    markingDefinitions {
                        edges {
                            node {
                                definition
                            }
                        }
                    }
                }
            }
        }
    }
`;

const dashboardLastStixDomainEntitiesQuery = graphql`
    query DashboardLastStixDomainEntitiesQuery($first: Int, $orderBy: StixDomainEntitiesOrdering, $orderMode: OrderingMode) {
        stixDomainEntities(first: $first, orderBy: $orderBy, orderMode: $orderMode) {
            edges {
                node {
                    id
                    type
                    name
                    description
                    updated_at
                    markingDefinitions {
                        edges {
                            node {
                                definition
                            }
                        }
                    }
                }
            }
        }
    }
`;

class Dashboard extends Component {
  render() {
    const { t, nsd, classes } = this.props;
    const stixDomainEntitiesTimeSeriesVariables = {
      field: 'created_at',
      operation: 'count',
      startDate: yearsAgo(1),
      endDate: now(),
      interval: 'day',
    };
    return (
      <div>
        <Grid container={true} spacing={16}>
          <Grid item={true} xs={3}>
            <Card raised={true} classes={{ root: classes.card }} style={{ height: 120 }}>
              <CardContent>
                <div className={classes.number}>
                  5 456
                </div>
                <div className={classes.diff}>
                  <ArrowUpward color='inherit' classes={{ root: classes.diffIcon }}/>
                  <div className={classes.diffNumber}>
                    5 123
                  </div>
                  <div className={classes.diffDescription}>
                    ({t('last 24h')})
                  </div>
                </div>
                <div className='clearfix'/>
                <div className={classes.title}>
                  {t('Total entities')}
                </div>
                <div className={classes.icon}>
                  <Database color='inherit' fontSize='large'/>
                </div>
              </CardContent>
            </Card>
            <Card raised={true} classes={{ root: classes.card }} style={{ height: 120 }}>
              <CardContent>
                <div className={classes.number}>
                  849
                </div>
                <div className={classes.diff}>
                  <ArrowUpward color='inherit' classes={{ root: classes.diffIcon }}/>
                  <div className={classes.diffNumber}>
                    5
                  </div>
                  <div className={classes.diffDescription}>
                    ({t('last 24h')})
                  </div>
                </div>
                <div className='clearfix'/>
                <div className={classes.title}>
                  {t('Total reports')}
                </div>
                <div className={classes.icon}>
                  <Assignment color='inherit' fontSize='large'/>
                </div>
              </CardContent>
            </Card>
          </Grid>
          <Grid item={true} xs={3}>
            <Card raised={true} classes={{ root: classes.card }} style={{ height: 120 }}>
              <CardContent>
                <div className={classes.number}>
                  12 568
                </div>
                <div className={classes.diff}>
                  <ArrowUpward color='inherit' classes={{ root: classes.diffIcon }}/>
                  <div className={classes.diffNumber}>
                    889
                  </div>
                  <div className={classes.diffDescription}>
                    ({t('last 24h')})
                  </div>
                </div>
                <div className='clearfix'/>
                <div className={classes.title}>
                  {t('Total observables')}
                </div>
                <div className={classes.icon}>
                  <Layers color='inherit' fontSize='large'/>
                </div>
              </CardContent>
            </Card>
            <Card raised={true} classes={{ root: classes.card }} style={{ height: 120 }}>
              <CardContent>
                <div className={classes.number}>
                  156
                </div>
                <div className={classes.diff}>
                  <ArrowUpward color='inherit' classes={{ root: classes.diffIcon }}/>
                  <div className={classes.diffNumber}>
                    8
                  </div>
                  <div className={classes.diffDescription}>
                    ({t('last 24h')})
                  </div>
                </div>
                <div className='clearfix'/>
                <div className={classes.title}>
                  {t('Total investigations')}
                </div>
                <div className={classes.icon}>
                  <DeviceHub color='inherit' fontSize='large'/>
                </div>
              </CardContent>
            </Card>
          </Grid>
          <Grid item={true} xs={6}>
            <Card raised={true} classes={{ root: classes.card }} style={{ height: 260 }}>
              <CardContent>
                <div className={classes.title}>
                  {t('Ingested entities')}
                </div>
                <div className={classes.graphContainer}>
                  <QueryRenderer
                    query={dashboardStixDomainEntitiesTimeSeriesQuery}
                    variables={stixDomainEntitiesTimeSeriesVariables}
                    render={({ props }) => {
                      if (props && props.stixDomainEntitiesTimeSeries) {
                        return (
                          <ResponsiveContainer height={180} width='100%'>
                            <BarChart data={props.stixDomainEntitiesTimeSeries} margin={{
                              top: 5, right: 5, bottom: 25, left: 5,
                            }}>
                              <XAxis dataKey='date' stroke='#ffffff' interval={15} angle={-45} textAnchor='end' tickFormatter={nsd}/>
                              <YAxis stroke='#ffffff'/>
                              <Tooltip
                                cursor={{ fill: 'rgba(0, 0, 0, 0.2)', stroke: 'rgba(0, 0, 0, 0.2)', strokeWidth: 2 }}
                                contentStyle={{ backgroundColor: 'rgba(255, 255, 255, 0.1)', fontSize: 12, borderRadius: 10 }}
                                labelFormatter={nsd}
                              />
                              <Bar fill={Theme.palette.primary.main} dataKey='value' barSize={10}/>
                            </BarChart>
                          </ResponsiveContainer>
                        );
                      }
                      return (
                        <div> &nbsp; </div>
                      );
                    }}
                  />
                </div>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
        <Grid container={true} spacing={16} style={{ marginTop: 20 }}>
          <Grid item={true} xs={6}>
            <Typography variant='h2' gutterBottom={true}>
              {t('Last internal reports')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <QueryRenderer
                query={dashboardLastReportsQuery}
                variables={{
                  reportClass: 'internal', first: 15, orderBy: 'published', orderMode: 'desc',
                }}
                render={({ props }) => {
                  if (props && props.reports) {
                    return (
                      <List>
                        {props.reports.edges.map((reportEdge) => {
                          const report = reportEdge.node;
                          const markingDefinition = head(pathOr([], ['markingDefinitions', 'edges'], report));
                          return (
                            <ListItem
                              key={report.id}
                              dense={true}
                              classes={{ default: classes.item }}
                              divider={true}
                              component={Link}
                              to={`/dashboard/reports/all/${report.id}`}
                            >
                              <ListItemIcon classes={{ root: classes.itemIcon }}>
                                <Description/>
                              </ListItemIcon>
                              <ListItemText primary={truncate(report.name, 70)} secondary={truncate(report.description, 70)}/>
                              <div style={{ minWidth: 100 }}>
                                {markingDefinition ? <ItemMarking key={markingDefinition.node.id} label={markingDefinition.node.definition}/> : ''}
                              </div>
                              <div style={inlineStyles.itemDate}>{nsd(report.published)}</div>
                            </ListItem>
                          );
                        })}
                      </List>
                    );
                  }
                  return (
                    <div> &nbsp; </div>
                  );
                }}
              />
            </Paper>
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant='h2' gutterBottom={true}>
              {t('Last modified entities')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <QueryRenderer
                query={dashboardLastStixDomainEntitiesQuery}
                variables={{ first: 15, orderBy: 'updated_at', orderMode: 'desc' }}
                render={({ props }) => {
                  if (props && props.stixDomainEntities) {
                    return (
                      <List>
                        {props.stixDomainEntities.edges.map((stixDomainEntityEdge) => {
                          const stixDomainEntity = stixDomainEntityEdge.node;
                          const markingDefinition = head(pathOr([], ['markingDefinitions', 'edges'], stixDomainEntity));
                          const link = resolveLink(stixDomainEntity.type);
                          return (
                            <ListItem
                              key={stixDomainEntity.id}
                              dense={true}
                              classes={{ default: classes.item }}
                              divider={true}
                              component={Link}
                              to={`${link}/${stixDomainEntity.id}`}
                            >
                              <ListItemIcon classes={{ root: classes.itemIcon }}>
                                <ItemIcon type={stixDomainEntity.type}/>
                              </ListItemIcon>
                              <ListItemText primary={truncate(stixDomainEntity.name, 70)} secondary={truncate(stixDomainEntity.description, 70)}/>
                              <div style={{ minWidth: 100 }}>
                                {markingDefinition ? <ItemMarking key={markingDefinition.node.id} label={markingDefinition.node.definition}/> : ''}
                              </div>
                              <div style={inlineStyles.itemDate}>{nsd(stixDomainEntity.updated_at)}</div>
                            </ListItem>
                          );
                        })}
                      </List>
                    );
                  }
                  return (
                    <div> &nbsp; </div>
                  );
                }}
              />
            </Paper>
          </Grid>
        </Grid>
      </div>
    );
  }
}

Dashboard.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
  md: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Dashboard);
