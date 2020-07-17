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
  AssignmentOutlined,
  LayersOutlined,
  WorkOutline,
  DescriptionOutlined,
} from '@material-ui/icons';
import { Database, HexagonOutline, GraphOutline } from 'mdi-material-ui';
import BarChart from 'recharts/lib/chart/BarChart';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import Bar from 'recharts/lib/cartesian/Bar';
import XAxis from 'recharts/lib/cartesian/XAxis';
import YAxis from 'recharts/lib/cartesian/YAxis';
import CartesianGrid from 'recharts/lib/cartesian/CartesianGrid';
import Tooltip from 'recharts/lib/component/Tooltip';
import { QueryRenderer } from '../../relay/environment';
import { yearsAgo, dayAgo, now } from '../../utils/Time';
import Theme from '../../components/ThemeDark';
import inject18n from '../../components/i18n';
import ItemNumberDifference from '../../components/ItemNumberDifference';
import ItemMarking from '../../components/ItemMarking';
import Loader from '../../components/Loader';
import Security, { KNOWLEDGE } from '../../utils/Security';
import { resolveLink } from '../../utils/Entity';
import ItemIcon from '../../components/ItemIcon';

const styles = (theme) => ({
  root: {
    flexGrow: 1,
  },
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 6,
    position: 'relative',
  },
  paper: {
    height: 420,
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 24,
  },
  itemIconSecondary: {
    marginRight: 0,
    color: theme.palette.secondary.main,
  },
  number: {
    marginTop: 10,
    float: 'left',
    fontSize: 30,
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
    fontWeight: 500,
    color: '#a8a8a8',
  },
  icon: {
    position: 'absolute',
    color: theme.palette.primary.main,
    top: 35,
    right: 20,
  },
  graphContainer: {
    width: '100%',
    margin: '20px 0 0 -30px',
  },
});

const inlineStyles = {
  itemAuthor: {
    width: 100,
    minWidth: 100,
    maxWidth: 100,
    paddingRight: 24,
    color: '#ffffff',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'left',
  },
  itemType: {
    width: 120,
    minWidth: 120,
    maxWidth: 120,
    paddingRight: 24,
    color: '#ffffff',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'left',
  },
  itemDate: {
    width: 100,
    minWidth: 100,
    maxWidth: 100,
    paddingRight: 24,
    color: '#ffffff',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'left',
  },
};

const dashboardStixDomainObjectsTimeSeriesQuery = graphql`
  query DashboardStixDomainObjectsTimeSeriesQuery(
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    stixDomainObjectsTimeSeries(
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      value
    }
  }
`;

const dashboardLastReportsQuery = graphql`
  query DashboardLastReportsQuery(
    $first: Int
    $orderBy: ReportsOrdering
    $orderMode: OrderingMode
  ) {
    reports(first: $first, orderBy: $orderBy, orderMode: $orderMode) {
      edges {
        node {
          id
          name
          description
          published
          createdBy {
            node {
              name
            }
          }
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

const dashboardLastStixDomainObjectsQuery = graphql`
  query DashboardLastStixDomainObjectsQuery(
    $first: Int
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
    $types: [String]
  ) {
    stixDomainObjects(
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      types: $types
    ) {
      edges {
        node {
          id
          entity_type
          name
          description
          updated_at
          createdBy {
            node {
              name
            }
          }
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

const dashboardLastNotesQuery = graphql`
  query DashboardLastNotesQuery(
    $first: Int
    $orderBy: NotesOrdering
    $orderMode: OrderingMode
  ) {
    notes(first: $first, orderBy: $orderBy, orderMode: $orderMode) {
      edges {
        node {
          id
          name
          created
          createdBy {
            node {
              name
            }
          }
          markingDefinitions {
            edges {
              node {
                definition
              }
            }
          }
          objectRefs {
            edges {
              node {
                id
                entity_type
              }
            }
          }
          observableRefs {
            edges {
              node {
                id
                entity_type
              }
            }
          }
          relationRefs {
            edges {
              node {
                id
                from {
                  id
                  entity_type
                }
              }
            }
          }
        }
      }
    }
  }
`;

const dashboardLastObservablesQuery = graphql`
  query DashboardLastObservablesQuery(
    $first: Int
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
  ) {
    stixCyberObservables(
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
    ) {
      edges {
        node {
          id
          entity_type
          observable_value
          description
          created_at
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

const dashboardStixDomainObjectsNumberQuery = graphql`
  query DashboardStixDomainObjectsNumberQuery(
    $types: [String]
    $endDate: DateTime
  ) {
    stixDomainObjectsNumber(types: $types, endDate: $endDate) {
      total
      count
    }
  }
`;

const dashboardStixCoreRelationshipsNumberQuery = graphql`
  query DashboardStixCoreRelationshipsNumberQuery(
    $type: String
    $endDate: DateTime
  ) {
    stixCoreRelationshipsNumber(type: $type, endDate: $endDate) {
      total
      count
    }
  }
`;

const dashboardStixCyberObservablesNumberQuery = graphql`
  query DashboardStixCyberObservablesNumberQuery(
    $types: [String]
    $endDate: DateTime
  ) {
    stixCyberObservablesNumber(types: $types, endDate: $endDate) {
      total
      count
    }
  }
`;

class Dashboard extends Component {
  render() {
    const {
      t, n, nsd, classes,
    } = this.props;
    const stixDomainObjectsTimeSeriesVariables = {
      field: 'created_at',
      operation: 'count',
      startDate: yearsAgo(1),
      endDate: now(),
      interval: 'day',
    };
    return (
      <div className={classes.root}>
        <Security
          needs={[KNOWLEDGE]}
          placeholder={t(
            'You do not have any access to the knowledge of this OpenCTI instance.',
          )}
        >
          <Grid container={true} spacing={3}>
            <Grid item={true} lg={3} xs={6}>
              <Card classes={{ root: classes.card }} style={{ height: 110 }}>
                <QueryRenderer
                  query={dashboardStixDomainObjectsNumberQuery}
                  variables={{ endDate: dayAgo() }}
                  render={({ props }) => {
                    if (props && props.stixDomainObjectsNumber) {
                      const { total } = props.stixDomainObjectsNumber;
                      const difference = total - props.stixDomainObjectsNumber.count;
                      return (
                        <CardContent>
                          <div className={classes.title}>
                            {t('Total entities')}
                          </div>
                          <div className={classes.number}>{n(total)}</div>
                          <ItemNumberDifference difference={difference} />
                          <div className={classes.icon}>
                            <Database color="inherit" fontSize="large" />
                          </div>
                        </CardContent>
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
              </Card>
              <Card classes={{ root: classes.card }} style={{ height: 110 }}>
                <QueryRenderer
                  query={dashboardStixCyberObservablesNumberQuery}
                  variables={{ endDate: dayAgo() }}
                  render={({ props }) => {
                    if (props && props.stixCyberObservablesNumber) {
                      const { total } = props.stixCyberObservablesNumber;
                      const difference = total - props.stixCyberObservablesNumber.count;
                      return (
                        <CardContent>
                          <div className={classes.title}>
                            {t('Total observables')}
                          </div>
                          <div className={classes.number}>{n(total)}</div>
                          <ItemNumberDifference difference={difference} />
                          <div className={classes.icon}>
                            <LayersOutlined color="inherit" fontSize="large" />
                          </div>
                        </CardContent>
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
              </Card>
            </Grid>
            <Grid item={true} lg={3} xs={6}>
              <Card classes={{ root: classes.card }} style={{ height: 110 }}>
                <QueryRenderer
                  query={dashboardStixCoreRelationshipsNumberQuery}
                  variables={{ type: 'stix_relation', endDate: dayAgo() }}
                  render={({ props }) => {
                    if (props && props.stixCoreRelationshipsNumber) {
                      const { total } = props.stixCoreRelationshipsNumber;
                      const difference = total - props.stixCoreRelationshipsNumber.count;
                      return (
                        <CardContent>
                          <div className={classes.title}>
                            {t('Total relationships')}
                          </div>
                          <div className={classes.number}>{n(total)}</div>
                          <ItemNumberDifference difference={difference} />
                          <div className={classes.icon}>
                            <GraphOutline color="inherit" fontSize="large" />
                          </div>
                        </CardContent>
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
              </Card>
              <Card classes={{ root: classes.card }} style={{ height: 110 }}>
                <QueryRenderer
                  query={dashboardStixDomainObjectsNumberQuery}
                  variables={{ types: ['report'], endDate: dayAgo() }}
                  render={({ props }) => {
                    if (props && props.stixDomainObjectsNumber) {
                      const { total } = props.stixDomainObjectsNumber;
                      const difference = total - props.stixDomainObjectsNumber.count;
                      return (
                        <CardContent>
                          <div className={classes.title}>
                            {t('Total reports')}
                          </div>
                          <div className={classes.number}>{n(total)}</div>
                          <ItemNumberDifference difference={difference} />
                          <div className={classes.icon}>
                            <AssignmentOutlined
                              color="inherit"
                              fontSize="large"
                            />
                          </div>
                        </CardContent>
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
              </Card>
            </Grid>
            <Grid item={true} lg={6} xs={12}>
              <Card classes={{ root: classes.card }} style={{ height: 240 }}>
                <CardContent>
                  <div className={classes.title}>{t('Ingested entities')}</div>
                  <div className={classes.graphContainer}>
                    <QueryRenderer
                      query={dashboardStixDomainObjectsTimeSeriesQuery}
                      variables={stixDomainObjectsTimeSeriesVariables}
                      render={({ props }) => {
                        if (props && props.stixDomainObjectsTimeSeries) {
                          return (
                            <ResponsiveContainer height={170} width="100%">
                              <BarChart
                                data={props.stixDomainObjectsTimeSeries}
                                margin={{
                                  top: 5,
                                  right: 5,
                                  bottom: 25,
                                  left: 20,
                                }}
                              >
                                <XAxis
                                  dataKey="date"
                                  stroke="#ffffff"
                                  interval={15}
                                  angle={-45}
                                  textAnchor="end"
                                  tickFormatter={nsd}
                                />
                                <YAxis stroke="#ffffff" />
                                <CartesianGrid
                                  strokeDasharray="2 2"
                                  stroke="#0f181f"
                                />
                                <Tooltip
                                  cursor={{
                                    fill: 'rgba(0, 0, 0, 0.2)',
                                    stroke: 'rgba(0, 0, 0, 0.2)',
                                    strokeWidth: 2,
                                  }}
                                  contentStyle={{
                                    backgroundColor: 'rgba(255, 255, 255, 0.1)',
                                    fontSize: 12,
                                    borderRadius: 10,
                                  }}
                                  labelFormatter={nsd}
                                />
                                <Bar
                                  fill={Theme.palette.primary.main}
                                  dataKey="value"
                                  barSize={10}
                                />
                              </BarChart>
                            </ResponsiveContainer>
                          );
                        }
                        return <Loader variant="inElement" />;
                      }}
                    />
                  </div>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} lg={6} xs={12}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Last modified entities')}
              </Typography>
              <Paper classes={{ root: classes.paper }} elevation={2}>
                <QueryRenderer
                  query={dashboardLastStixDomainObjectsQuery}
                  variables={{
                    first: 8,
                    orderBy: 'modified',
                    orderMode: 'desc',
                    types: [
                      'Threat-Actor',
                      'Intrusion-Set',
                      'Campaign',
                      'XOpenctiIncident',
                      'Malware',
                      'Attack-Pattern',
                      'Course-of-Action',
                      'Tool',
                      'Vulnerability',
                    ],
                  }}
                  render={({ props }) => {
                    if (props && props.stixDomainObjects) {
                      return (
                        <List>
                          {props.stixDomainObjects.edges.map(
                            (stixDomainObjectEdge) => {
                              const stixDomainObject = stixDomainObjectEdge.node;
                              const stixDomainObjectLink = `${resolveLink(
                                stixDomainObject.entity_type,
                              )}/${stixDomainObject.id}`;
                              const markingDefinition = head(
                                pathOr(
                                  [],
                                  ['markingDefinitions', 'edges'],
                                  stixDomainObject,
                                ),
                              );
                              return (
                                <ListItem
                                  key={stixDomainObject.id}
                                  dense={true}
                                  button={true}
                                  classes={{ root: classes.item }}
                                  divider={true}
                                  component={Link}
                                  to={stixDomainObjectLink}
                                >
                                  <ListItemIcon>
                                    <ItemIcon
                                      type={stixDomainObject.entity_type}
                                      color="#00bcd4"
                                    />
                                  </ListItemIcon>
                                  <ListItemText
                                    primary={
                                      <div className={classes.itemText}>
                                        {stixDomainObject.name}
                                      </div>
                                    }
                                  />
                                  <div style={inlineStyles.itemAuthor}>
                                    {pathOr(
                                      '',
                                      ['createdBy', 'node', 'name'],
                                      stixDomainObject,
                                    )}
                                  </div>
                                  <div style={inlineStyles.itemDate}>
                                    {nsd(stixDomainObject.modified)}
                                  </div>
                                  <div
                                    style={{
                                      width: 110,
                                      maxWidth: 110,
                                      minWidth: 110,
                                      paddingRight: 20,
                                    }}
                                  >
                                    {markingDefinition ? (
                                      <ItemMarking
                                        key={markingDefinition.node.id}
                                        label={
                                          markingDefinition.node.definition
                                        }
                                        variant="inList"
                                      />
                                    ) : (
                                      ''
                                    )}
                                  </div>
                                </ListItem>
                              );
                            },
                          )}
                        </List>
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
              </Paper>
            </Grid>
            <Grid item={true} lg={6} xs={12}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Last notes')}
              </Typography>
              <Paper classes={{ root: classes.paper }} elevation={2}>
                <QueryRenderer
                  query={dashboardLastNotesQuery}
                  variables={{
                    first: 8,
                    orderBy: 'created',
                    orderMode: 'desc',
                  }}
                  render={({ props }) => {
                    if (props && props.notes) {
                      return (
                        <List>
                          {props.notes.edges.map((noteEdge) => {
                            const note = noteEdge.node;
                            let noteLink;
                            if (note.objectRefs.edges.length > 0) {
                              noteLink = `${resolveLink(
                                note.objectRefs.edges[0].node.entity_type,
                              )}/${note.objectRefs.edges[0].node.id}`;
                            } else if (note.observableRefs.edges.length > 0) {
                              noteLink = `${resolveLink(
                                note.observableRefs.edges[0].node.entity_type,
                              )}/${note.observableRefs.edges[0].node.id}`;
                            } else if (note.relationRefs.edges.length > 0) {
                              noteLink = `${resolveLink(
                                note.relationRefs.edges[0].node.from.entity_type,
                              )}/${
                                note.relationRefs.edges[0].node.from.id
                              }/knowledge/relations/${
                                note.relationRefs.edges[0].node.id
                              }`;
                            }
                            const markingDefinition = head(
                              pathOr([], ['markingDefinitions', 'edges'], note),
                            );
                            return (
                              <ListItem
                                key={note.id}
                                dense={true}
                                button={true}
                                classes={{ root: classes.item }}
                                divider={true}
                                component={Link}
                                to={noteLink}
                              >
                                <ListItemIcon>
                                  <WorkOutline color="primary" />
                                </ListItemIcon>
                                <ListItemText
                                  primary={
                                    <div className={classes.itemText}>
                                      {note.name}
                                    </div>
                                  }
                                />
                                <div style={inlineStyles.itemAuthor}>
                                  {pathOr(
                                    '',
                                    ['createdBy', 'node', 'name'],
                                    note,
                                  )}
                                </div>
                                <div style={inlineStyles.itemDate}>
                                  {nsd(note.created)}
                                </div>
                                <div
                                  style={{
                                    width: 110,
                                    maxWidth: 110,
                                    minWidth: 110,
                                    paddingRight: 20,
                                  }}
                                >
                                  {markingDefinition ? (
                                    <ItemMarking
                                      key={markingDefinition.node.id}
                                      label={markingDefinition.node.definition}
                                      variant="inList"
                                    />
                                  ) : (
                                    ''
                                  )}
                                </div>
                              </ListItem>
                            );
                          })}
                        </List>
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
              </Paper>
            </Grid>
            <Grid item={true} lg={6} xs={12} style={{ marginBottom: 30 }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Last reports')}
              </Typography>
              <Paper classes={{ root: classes.paper }} elevation={2}>
                <QueryRenderer
                  query={dashboardLastReportsQuery}
                  variables={{
                    first: 8,
                    orderBy: 'published',
                    orderMode: 'desc',
                  }}
                  render={({ props }) => {
                    if (props && props.reports) {
                      return (
                        <List>
                          {props.reports.edges.map((reportEdge) => {
                            const report = reportEdge.node;
                            const markingDefinition = head(
                              pathOr(
                                [],
                                ['markingDefinitions', 'edges'],
                                report,
                              ),
                            );
                            return (
                              <ListItem
                                key={report.id}
                                dense={true}
                                button={true}
                                classes={{ root: classes.item }}
                                divider={true}
                                component={Link}
                                to={`/dashboard/reports/all/${report.id}`}
                              >
                                <ListItemIcon>
                                  <DescriptionOutlined color="primary" />
                                </ListItemIcon>
                                <ListItemText
                                  primary={
                                    <div className={classes.itemText}>
                                      {report.name}
                                    </div>
                                  }
                                />
                                <div style={inlineStyles.itemAuthor}>
                                  {pathOr(
                                    '',
                                    ['createdBy', 'node', 'name'],
                                    report,
                                  )}
                                </div>
                                <div style={inlineStyles.itemDate}>
                                  {nsd(report.published)}
                                </div>
                                <div
                                  style={{
                                    width: 110,
                                    maxWidth: 110,
                                    minWidth: 110,
                                    paddingRight: 20,
                                  }}
                                >
                                  {markingDefinition ? (
                                    <ItemMarking
                                      key={markingDefinition.node.id}
                                      label={markingDefinition.node.definition}
                                      variant="inList"
                                    />
                                  ) : (
                                    ''
                                  )}
                                </div>
                              </ListItem>
                            );
                          })}
                        </List>
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
              </Paper>
            </Grid>
            <Grid item={true} lg={6} xs={12} style={{ marginBottom: 30 }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Last observables')}
              </Typography>
              <Paper classes={{ root: classes.paper }} elevation={2}>
                <QueryRenderer
                  query={dashboardLastObservablesQuery}
                  variables={{
                    first: 8,
                    orderBy: 'created_at',
                    orderMode: 'desc',
                  }}
                  render={({ props }) => {
                    if (props && props.stixCyberObservables) {
                      return (
                        <List>
                          {props.stixCyberObservables.edges.map(
                            (stixCyberObservableEdge) => {
                              const stixCyberObservable = stixCyberObservableEdge.node;
                              const markingDefinition = head(
                                pathOr(
                                  [],
                                  ['markingDefinitions', 'edges'],
                                  stixCyberObservable,
                                ),
                              );
                              return (
                                <ListItem
                                  key={stixCyberObservable.id}
                                  dense={true}
                                  button={true}
                                  classes={{ root: classes.item }}
                                  divider={true}
                                  component={Link}
                                  to={`/dashboard/signatures/observables/${stixCyberObservable.id}`}
                                >
                                  <ListItemIcon>
                                    <HexagonOutline color="primary" />
                                  </ListItemIcon>
                                  <ListItemText
                                    primary={
                                      <div className={classes.itemText}>
                                        {stixCyberObservable.observable_value}
                                      </div>
                                    }
                                  />
                                  <div style={inlineStyles.itemType}>
                                    {t(
                                      `observable_${stixCyberObservable.entity_type}`,
                                    )}
                                  </div>
                                  <div style={inlineStyles.itemDate}>
                                    {nsd(stixCyberObservable.created_at)}
                                  </div>
                                  <div
                                    style={{
                                      width: 110,
                                      maxWidth: 110,
                                      minWidth: 110,
                                      paddingRight: 20,
                                    }}
                                  >
                                    {markingDefinition ? (
                                      <ItemMarking
                                        key={markingDefinition.node.id}
                                        label={
                                          markingDefinition.node.definition
                                        }
                                        variant="inList"
                                      />
                                    ) : (
                                      ''
                                    )}
                                  </div>
                                </ListItem>
                              );
                            },
                          )}
                        </List>
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
              </Paper>
            </Grid>
          </Grid>
        </Security>
      </div>
    );
  }
}

Dashboard.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  n: PropTypes.func,
  nsd: PropTypes.func,
  md: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(Dashboard);
