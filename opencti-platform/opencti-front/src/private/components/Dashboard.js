/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import {
  compose, head, pathOr, assoc, map, pluck, last, or,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withTheme, withStyles } from '@material-ui/core/styles';
import Card from '@material-ui/core/Card';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import CardContent from '@material-ui/core/CardContent';
import { DescriptionOutlined } from '@material-ui/icons';
import {
  Database,
  GraphOutline,
  HexagonMultipleOutline,
} from 'mdi-material-ui';
import {
  BarChart,
  AreaChart,
  Cell,
  Bar,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { QueryRenderer } from '../../relay/environment';
import {
  yearsAgo, dayAgo, now, monthsAgo,
} from '../../utils/Time';
import inject18n from '../../components/i18n';
import ItemNumberDifference from '../../components/ItemNumberDifference';
import Loader from '../../components/Loader';
import Security, { KNOWLEDGE } from '../../utils/Security';
import { resolveLink } from '../../utils/Entity';
import ItemIcon from '../../components/ItemIcon';
import { hexToRGB, itemColor } from '../../utils/Colors';
import CyioDashboard from './workspaces/dashboards/CyioDashboard';
import { truncate } from '../../utils/String';
import StixCoreRelationshipsHorizontalBars from './common/stix_core_relationships/StixCoreRelationshipsHorizontalBars';
import LocationMiniMapTargets from './common/location/LocationMiniMapTargets';
import { computeLevel } from '../../utils/Number';
import ItemMarkings from '../../components/ItemMarkings';
import ImportFreshdeskScript from '../../utils/freshdesk';
import TopBar from './nav/TopBar';
import { toastGenericError } from '../../utils/bakedToast';
import DashboardSettings from './DashboardSettings';

const styles = (theme) => ({
  root: {
    margin: '0 0 1rem 0',
  },
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 6,
    position: 'relative',
  },
  paper: {
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
    color: theme.palette.text.secondary,
  },
  icon: {
    position: 'absolute',
    color: theme.palette.primary.main,
    top: 35,
    right: 20,
  },
  graphContainer: {
    width: '100%',
    padding: '20px 20px 0 0',
  },
  labelsCloud: {
    width: '100%',
    height: 300,
  },
  label: {
    width: '100%',
    height: 100,
    padding: 15,
  },
  labelNumber: {
    fontSize: 30,
    fontWeight: 500,
  },
  labelValue: {
    fontSize: 15,
  },
  itemAuthor: {
    width: 200,
    minWidth: 200,
    maxWidth: 200,
    paddingRight: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'left',
  },
  itemType: {
    width: 100,
    minWidth: 100,
    maxWidth: 100,
    paddingRight: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'left',
  },
  itemDate: {
    width: 120,
    minWidth: 120,
    maxWidth: 120,
    paddingRight: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'left',
  },
});

const dashboardStixMetaRelationshipsDistributionQuery = graphql`
  query DashboardStixMetaRelationshipsDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $relationship_type: String
    $toTypes: [String]
    $startDate: DateTime
    $endDate: DateTime
    $limit: Int
  ) {
    stixMetaRelationshipsDistribution(
      field: $field
      operation: $operation
      relationship_type: $relationship_type
      toTypes: $toTypes
      startDate: $startDate
      endDate: $endDate
      limit: $limit
    ) {
      label
      value
      entity {
        ... on BasicObject {
          entity_type
        }
        ... on Label {
          value
          color
        }
      }
    }
  }
`;

export const dashboardStixCoreRelationshipsDistributionQuery = graphql`
  query DashboardStixCoreRelationshipsDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $relationship_type: String
    $toTypes: [String]
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $limit: Int
  ) {
    stixCoreRelationshipsDistribution(
      field: $field
      operation: $operation
      relationship_type: $relationship_type
      toTypes: $toTypes
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      limit: $limit
    ) {
      label
      value
      entity {
        ... on BasicObject {
          entity_type
        }
        ... on BasicRelationship {
          entity_type
        }
        ... on Country {
          name
          x_opencti_aliases
          latitude
          longitude
        }
      }
    }
  }
`;

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
          created_at
          ... on Report {
            name
          }
          ... on Note {
            attribute_abstract
            content
          }
          ... on Opinion {
            opinion
            explanation
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            edges {
              node {
                id
                definition
              }
            }
          }
        }
      }
    }
  }
`;

const dashboardStixCyberObservablesDistributionQuery = graphql`
  query DashboardStixCyberObservablesDistributionQuery(
    $field: String!
    $operation: String!
  ) {
    stixCyberObservablesDistribution(field: $field, operation: $operation) {
      label
      value
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

// const dashboardCustomDashboardQuery = graphql`
// query DashboardCustomDashboardQuery($id: String!) {
//   workspace(id: $id) {
//     id
//     name
//     ...CyioDashboard_workspace
//   }
// }
// `;

const dashboardCustomDashboardQuery = graphql`
query DashboardCustomDashboardQuery {
  workspace(id: "15794f5d-b071-4ddc-9567-d786149fa74f") {
    id
    name
    ...CyioDashboard_workspace
  }
}
`;

class Dashboard extends Component {
  constructor(props) {
    super(props);
    this.state = {
      dashboard: or(localStorage.getItem('view-dashboard'), 'default'),
    };
  }

  tickFormatter(title) {
    return truncate(this.props.t(`entity_${title}`), 10);
  }

  renderDefaultDashboard() {
    const {
      t, n, fsd, mtd, classes, theme,
    } = this.props;
    ImportFreshdeskScript();
    return (
      <div className={classes.root}>
        <Security
          needs={[KNOWLEDGE]}
          placeholder={t(
            'You do not have any access to the knowledge of this OpenCTI instance.',
          )}
        >
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={3}>
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
                          <ItemNumberDifference
                            difference={difference}
                            description={t('24 hours')}
                          />
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
            </Grid>
            <Grid item={true} xs={3}>
              <Card classes={{ root: classes.card }} style={{ height: 110 }}>
                <QueryRenderer
                  query={dashboardStixCoreRelationshipsNumberQuery}
                  variables={{
                    type: 'stix-core-relationship',
                    endDate: dayAgo(),
                  }}
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
                          <ItemNumberDifference
                            difference={difference}
                            description={t('24 hours')}
                          />
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
            </Grid>
            <Grid item={true} xs={3}>
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
                          <ItemNumberDifference
                            difference={difference}
                            description={t('24 hours')}
                          />
                          <div className={classes.icon}>
                            <DescriptionOutlined
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
            <Grid item={true} xs={3}>
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
                          <ItemNumberDifference
                            difference={difference}
                            description={t('24 hours')}
                          />
                          <div className={classes.icon}>
                            <HexagonMultipleOutline
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
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={4}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Top Labels (3 last months)')}
              </Typography>
              <Paper
                classes={{ root: classes.paper }}
                elevation={2}
                style={{ height: 300 }}
              >
                <QueryRenderer
                  query={dashboardStixMetaRelationshipsDistributionQuery}
                  variables={{
                    field: 'internal_id',
                    operation: 'count',
                    relationship_type: 'object-label',
                    toTypes: ['Label'],
                    startDate: monthsAgo(3),
                    endDate: now(),
                    limit: 9,
                  }}
                  render={({ props }) => {
                    if (
                      props
                      && props.stixMetaRelationshipsDistribution
                      && props.stixMetaRelationshipsDistribution.length > 0
                    ) {
                      return (
                        <div className={classes.labelsCloud}>
                          <Grid container={true} spacing={0}>
                            {props.stixMetaRelationshipsDistribution.map(
                              (line) => (
                                <Grid
                                  key={line.label}
                                  item={true}
                                  xs={4}
                                  style={{ padding: 0 }}
                                >
                                  <div
                                    className={classes.label}
                                    style={{
                                      color: line.entity.color,
                                      borderColor: line.entity.color,
                                      backgroundColor: hexToRGB(
                                        line.entity.color,
                                      ),
                                    }}
                                  >
                                    <div className={classes.labelNumber}>
                                      {n(line.value)}
                                    </div>
                                    <div className={classes.labelValue}>
                                      {truncate(line.entity.value, 15)}
                                    </div>
                                  </div>
                                </Grid>
                              ),
                            )}
                          </Grid>
                        </div>
                      );
                    }
                    if (props) {
                      return (
                        <div
                          style={{
                            display: 'table',
                            height: '100%',
                            width: '100%',
                          }}
                        >
                          <span
                            style={{
                              display: 'table-cell',
                              verticalAlign: 'middle',
                              textAlign: 'center',
                            }}
                          >
                            {t('No entities of this type has been found.')}
                          </span>
                        </div>
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
              </Paper>
            </Grid>
            <Grid item={true} xs={8}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Ingested entities')}
              </Typography>
              <Paper
                classes={{ root: classes.paper }}
                elevation={2}
                style={{ height: 300 }}
              >
                <QueryRenderer
                  query={dashboardStixDomainObjectsTimeSeriesQuery}
                  variables={{
                    field: 'created_at',
                    operation: 'count',
                    startDate: yearsAgo(1),
                    endDate: now(),
                    interval: 'month',
                  }}
                  render={({ props }) => {
                    if (props && props.stixDomainObjectsTimeSeries) {
                      return (
                        <div className={classes.graphContainer}>
                          <ResponsiveContainer height={270} width="100%">
                            <AreaChart
                              data={props.stixDomainObjectsTimeSeries}
                              margin={{
                                top: 0,
                                right: 0,
                                bottom: 0,
                                left: -10,
                              }}
                            >
                              <CartesianGrid
                                strokeDasharray="2 2"
                                stroke={theme.palette.action.grid}
                              />
                              <XAxis
                                dataKey="date"
                                stroke={theme.palette.text.primary}
                                interval={0}
                                textAnchor="end"
                                tickFormatter={mtd}
                              />
                              <YAxis stroke={theme.palette.text.primary} />
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
                                labelFormatter={fsd}
                              />
                              <Area
                                type="monotone"
                                dataKey="value"
                                stroke={theme.palette.primary.main}
                                strokeWidth={2}
                                fill={theme.palette.primary.main}
                                fillOpacity={0.1}
                              />
                            </AreaChart>
                          </ResponsiveContainer>
                        </div>
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
              </Paper>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3} style={{ marginTop: 20 }}>
            <Grid item={true} xs={6}>
              <StixCoreRelationshipsHorizontalBars
                height={400}
                relationshipType="stix-core-relationship"
                toTypes={[
                  'Threat-Actor',
                  'Intrusion-Set',
                  'Campaign',
                  'Malware',
                  'Tool',
                  'Vulnerability',
                ]}
                title={t('Top 10 active entities (3 last months)')}
                field="internal_id"
                startDate={monthsAgo(3)}
                endDate={now()}
                dateAttribute="created_at"
              />
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Targeted countries (3 last months)')}
              </Typography>
              <Paper
                classes={{ root: classes.paper }}
                elevation={2}
                style={{ height: 400 }}
              >
                <QueryRenderer
                  query={dashboardStixCoreRelationshipsDistributionQuery}
                  variables={{
                    field: 'internal_id',
                    operation: 'count',
                    relationship_type: 'targets',
                    toTypes: ['Country'],
                    startDate: monthsAgo(3),
                    endDate: now(),
                    dateAttribute: 'created_at',
                    limit: 20,
                  }}
                  render={({ props }) => {
                    if (
                      props
                      && props.stixCoreRelationshipsDistribution
                      && props.stixCoreRelationshipsDistribution.length > 0
                    ) {
                      const values = pluck(
                        'value',
                        props.stixCoreRelationshipsDistribution,
                      );
                      const countries = map(
                        (x) => assoc(
                          'level',
                          computeLevel(
                            x.value,
                            last(values),
                            head(values) + 1,
                          ),
                          x.entity,
                        ),
                        props.stixCoreRelationshipsDistribution,
                      );
                      return (
                        <LocationMiniMapTargets
                          center={[48.8566969, 2.3514616]}
                          countries={countries}
                          zoom={2}
                        />
                      );
                    }
                    return (
                      <LocationMiniMapTargets
                        center={[48.8566969, 2.3514616]}
                        zoom={2}
                      />
                    );
                  }}
                />
              </Paper>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3} style={{ marginTop: 20 }}>
            <Grid item={true} xs={8}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Last ingested analysis (creation date in the platform)')}
              </Typography>
              <Paper
                classes={{ root: classes.paper }}
                elevation={2}
                style={{ height: 420 }}
              >
                <QueryRenderer
                  query={dashboardLastStixDomainObjectsQuery}
                  variables={{
                    first: 8,
                    orderBy: 'created_at',
                    orderMode: 'desc',
                    types: ['Report', 'Note', 'Opinion'],
                  }}
                  render={({ props }) => {
                    if (
                      props
                      && props.stixDomainObjects
                      && props.stixDomainObjects.edges.length > 0
                    ) {
                      return (
                        <List>
                          {props.stixDomainObjects.edges.map(
                            (stixDomainObjectEdge) => {
                              const stixDomainObject = stixDomainObjectEdge.node;
                              const stixDomainObjectLink = `${resolveLink(
                                stixDomainObject.entity_type,
                              )}/${stixDomainObject.id}`;
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
                                      color={theme.palette.primary.main}
                                    />
                                  </ListItemIcon>
                                  <div className={classes.itemType}>
                                    {t(
                                      `entity_${stixDomainObject.entity_type}`,
                                    )}
                                  </div>
                                  <ListItemText
                                    primary={
                                      <div className={classes.itemText}>
                                        {stixDomainObject.name
                                          || stixDomainObject.attribute_abstract
                                          || truncate(
                                            stixDomainObject.content,
                                            30,
                                          )
                                          || stixDomainObject.opinion}
                                      </div>
                                    }
                                  />
                                  <div className={classes.itemAuthor}>
                                    {pathOr(
                                      '',
                                      ['createdBy', 'name'],
                                      stixDomainObject,
                                    )}
                                  </div>
                                  <div className={classes.itemDate}>
                                    {fsd(stixDomainObject.created_at)}
                                  </div>
                                  <div
                                    style={{
                                      width: 110,
                                      maxWidth: 110,
                                      minWidth: 110,
                                      paddingRight: 20,
                                    }}
                                  >
                                    <ItemMarkings
                                      markingDefinitions={pathOr(
                                        [],
                                        ['objectMarking', 'edges'],
                                        stixDomainObject,
                                      )}
                                      limit={1}
                                      variant="inList"
                                    />
                                  </div>
                                </ListItem>
                              );
                            },
                          )}
                        </List>
                      );
                    }
                    if (props) {
                      return (
                        <div
                          style={{
                            display: 'table',
                            height: '100%',
                            width: '100%',
                          }}
                        >
                          <span
                            style={{
                              display: 'table-cell',
                              verticalAlign: 'middle',
                              textAlign: 'center',
                            }}
                          >
                            {t('No entities of this type has been found.')}
                          </span>
                        </div>
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
              </Paper>
            </Grid>
            <Grid item={true} xs={4}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Observables distribution')}
              </Typography>
              <Paper
                classes={{ root: classes.paper }}
                elevation={2}
                style={{ height: 420 }}
              >
                <QueryRenderer
                  query={dashboardStixCyberObservablesDistributionQuery}
                  variables={{ field: 'entity_type', operation: 'count' }}
                  render={({ props }) => {
                    if (
                      props
                      && props.stixCyberObservablesDistribution
                      && props.stixCyberObservablesDistribution.length > 0
                    ) {
                      return (
                        <div className={classes.graphContainer}>
                          <ResponsiveContainer height={420} width="100%">
                            <BarChart
                              layout="vertical"
                              data={props.stixCyberObservablesDistribution}
                              margin={{
                                top: 0,
                                right: 0,
                                bottom: 20,
                                left: 0,
                              }}
                            >
                              <XAxis
                                type="number"
                                dataKey="value"
                                stroke={theme.palette.text.primary}
                                allowDecimals={false}
                              />
                              <YAxis
                                stroke={theme.palette.text.primary}
                                dataKey="label"
                                type="category"
                                angle={-30}
                                textAnchor="end"
                                tickFormatter={this.tickFormatter.bind(this)}
                              />
                              <CartesianGrid
                                strokeDasharray="2 2"
                                stroke={theme.palette.action.grid}
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
                              />
                              <Bar
                                fill={theme.palette.primary.main}
                                dataKey="value"
                                barSize={15}
                              >
                                {props.stixCyberObservablesDistribution.map(
                                  (entry, index) => (
                                    <Cell
                                      key={`cell-${index}`}
                                      fill={itemColor(entry.label)}
                                    />
                                  ),
                                )}
                              </Bar>
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                      );
                    }
                    if (props) {
                      return (
                        <div
                          style={{
                            display: 'table',
                            height: '100%',
                            width: '100%',
                          }}
                        >
                          <span
                            style={{
                              display: 'table-cell',
                              verticalAlign: 'middle',
                              textAlign: 'center',
                            }}
                          >
                            {t('No entities of this type has been found.')}
                          </span>
                        </div>
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

  renderCustomDashboard() {
    return (
      <>
        <QueryRenderer
          query={dashboardCustomDashboardQuery}
          variables={{ id: this.state.dashboard }}
          render={({ error, props }) => {
            if (error) {
              toastGenericError('Request Failed');
            }
            if (props) {
              if(!props.workspace) {
                return <DashboardSettings
                          dashboard={this.state.dashboard}
                          handleChangeDashboard={this.handleChangeDashboard.bind(this)}
                          isDashboard={false}
                        />
              }
              return (
                <CyioDashboard
                  workspace={props.workspace}
                  noToolbar={true}
                />
              );
            }
            return <Loader />;
          }}
        />
      </>
    );
  }

  handleChangeDashboard = (event) => {
    this.setState({ dashboard: event.target.value });
    localStorage.setItem('view-dashboard', event.target.value);
    this.props.history.push('/dashboard');
  }

  render() {
    return (
      <>
        <TopBar
          dashboard={this.state.dashboard}
          handleChangeDashboard={this.handleChangeDashboard.bind(this)}
        />
        {this.state.dashboard === 'default' ? (
          this.renderDefaultDashboard()
        ) : (
          this.renderCustomDashboard()
        )}
      </>
    );
  }
}

Dashboard.propTypes = {
  theme: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  n: PropTypes.func,
  fsd: PropTypes.func,
  mtd: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(inject18n, withTheme, withStyles(styles))(Dashboard);
