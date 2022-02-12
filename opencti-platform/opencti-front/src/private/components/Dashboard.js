import React, { Suspense } from 'react';
import { Link } from 'react-router-dom';
import {
  head, pathOr, assoc, map, pluck, last,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { makeStyles, useTheme } from '@mui/styles';
import Card from '@mui/material/Card';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import CardContent from '@mui/material/CardContent';
import { DescriptionOutlined } from '@mui/icons-material';
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
import Slide from '@mui/material/Slide';
import { useLazyLoadQuery } from 'react-relay';
import {
  yearsAgo, dayAgo, now, monthsAgo,
} from '../../utils/Time';
import { useFormatter } from '../../components/i18n';
import ItemNumberDifference from '../../components/ItemNumberDifference';
import Loader from '../../components/Loader';
import Security, { EXPLORE, KNOWLEDGE } from '../../utils/Security';
import { resolveLink } from '../../utils/Entity';
import ItemIcon from '../../components/ItemIcon';
import { hexToRGB, itemColor } from '../../utils/Colors';
import { truncate } from '../../utils/String';
import StixCoreRelationshipsHorizontalBars from './common/stix_core_relationships/StixCoreRelationshipsHorizontalBars';
import LocationMiniMapTargets from './common/location/LocationMiniMapTargets';
import { computeLevel } from '../../utils/Number';
import ItemMarkings from '../../components/ItemMarkings';
import DashboardView from './workspaces/dashboards/Dashboard';

import { useViewStorage } from '../../utils/ListParameters';
import TopBar from './nav/TopBar';
import ErrorNotFound from '../../components/ErrorNotFound';

// region styles
const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';
const useStyles = makeStyles((theme) => ({
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
}));
// endregion

// region inner components
const NoTableElement = () => {
  const { t } = useFormatter();
  return <div style={{ display: 'table', height: '100%', width: '100%' }}>
    <span style={{ display: 'table-cell', verticalAlign: 'middle', textAlign: 'center' }}>
      {t('No entities of this type has been found.')}
    </span>
  </div>;
};
const TotalEntitiesCard = ({ title, options, Icon }) => {
  const classes = useStyles();
  const { t, n } = useFormatter();
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
  const data = useLazyLoadQuery(dashboardStixDomainObjectsNumberQuery, options);
  const { total } = data.stixDomainObjectsNumber;
  const difference = total - data.stixDomainObjectsNumber.count;
  return <CardContent>
      <div className={classes.title}>{t(title)}</div>
      <div className={classes.number}>{n(total)}</div>
      <ItemNumberDifference difference={difference} description={t('24 hours')}/>
      <div className={classes.icon}>
        <Icon color="inherit" fontSize="large" />
      </div>
  </CardContent>;
};
const TotalRelationshipsCard = ({ title, options, Icon }) => {
  const classes = useStyles();
  const { t, n } = useFormatter();
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
  const data = useLazyLoadQuery(dashboardStixCoreRelationshipsNumberQuery, options);
  const { total } = data.stixCoreRelationshipsNumber;
  const difference = total - data.stixCoreRelationshipsNumber.count;
  return <CardContent>
    <div className={classes.title}>{t(title)}</div>
    <div className={classes.number}>{n(total)}</div>
    <ItemNumberDifference difference={difference} description={t('24 hours')}/>
    <div className={classes.icon}>
      <Icon color="inherit" fontSize="large" />
    </div>
  </CardContent>;
};
const TotalObservablesCard = ({ title, options, Icon }) => {
  const classes = useStyles();
  const { t, n } = useFormatter();
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
  const data = useLazyLoadQuery(dashboardStixCyberObservablesNumberQuery, options);
  const { total } = data.stixCyberObservablesNumber;
  const difference = total - data.stixCyberObservablesNumber.count;
  return <CardContent>
    <div className={classes.title}>{t(title)}</div>
    <div className={classes.number}>{n(total)}</div>
    <ItemNumberDifference difference={difference} description={t('24 hours')}/>
    <div className={classes.icon}>
      <Icon color="inherit" fontSize="large" />
    </div>
  </CardContent>;
};
const TopLabelsCard = () => {
  const classes = useStyles();
  const { n } = useFormatter();
  const dashboardStixMetaRelationshipsDistributionQuery = graphql`
    query DashboardStixMetaRelationshipsDistributionQuery(
      $field: String!
      $operation: StatsOperation!
      $relationship_type: String
      $toTypes: [String]
      $startDate: DateTime
      $endDate: DateTime
      $dateAttribute: String
      $limit: Int
    ) {
      stixMetaRelationshipsDistribution(
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
          ... on Label {
            value
            color
          }
        }
      }
    }
  `;
  const data = useLazyLoadQuery(dashboardStixMetaRelationshipsDistributionQuery, {
    field: 'internal_id',
    operation: 'count',
    relationship_type: 'object-label',
    toTypes: ['Label'],
    startDate: monthsAgo(3),
    endDate: now(),
    limit: 9,
  });
  const distribution = data.stixMetaRelationshipsDistribution;
  if (distribution.length === 0) {
    return <NoTableElement/>;
  }
  return <div className={classes.labelsCloud}>
    <Grid container={true} spacing={0}>
      {distribution.map((line) => (
      <Grid key={line.label} item={true} xs={4} style={{ padding: 0 }}>
          <div className={classes.label} style={{
            color: line.entity.color,
            borderColor: line.entity.color,
            backgroundColor: hexToRGB(line.entity.color),
          }}>
            <div className={classes.labelNumber}>
              {n(line.value)}
            </div>
            <div className={classes.labelValue}>
              {truncate(line.entity.value, 15)}
            </div>
          </div>
        </Grid>
      ))}
      </Grid>
    </div>;
};
const IngestedEntitiesGraph = () => {
  const classes = useStyles();
  const theme = useTheme();
  const { mtd, fsd } = useFormatter();
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
  const data = useLazyLoadQuery(dashboardStixDomainObjectsTimeSeriesQuery, {
    field: 'created_at',
    operation: 'count',
    startDate: yearsAgo(1),
    endDate: now(),
    interval: 'month',
  });
  return <div className={classes.graphContainer}>
    <ResponsiveContainer height={270} width="100%">
      <AreaChart data={data.stixDomainObjectsTimeSeries} margin={{
        top: 0,
        right: 0,
        bottom: 0,
        left: -10,
      }}>
        <CartesianGrid strokeDasharray="2 2" stroke={theme.palette.action.grid}/>
        <XAxis dataKey="date"
            stroke={theme.palette.text.primary}
            interval={0}
            textAnchor="end"
            tickFormatter={mtd}/>
        <YAxis stroke={theme.palette.text.primary} />
        <Tooltip cursor={{
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
        <Area type="monotone"
            dataKey="value"
            stroke={theme.palette.primary.main}
            strokeWidth={2}
            fill={theme.palette.primary.main}
            fillOpacity={0.1}
        />
      </AreaChart>
    </ResponsiveContainer>
  </div>;
};
const TargetedCountries = ({ timeField }) => {
  const dashboardStixCoreRelationshipsDistributionQuery = graphql`
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
  const data = useLazyLoadQuery(dashboardStixCoreRelationshipsDistributionQuery, {
    field: 'internal_id',
    operation: 'count',
    relationship_type: 'targets',
    toTypes: ['Country'],
    startDate: monthsAgo(3),
    endDate: now(),
    dateAttribute: timeField === 'functional' ? 'start_time' : 'created_at',
    limit: 20,
  });
  const values = pluck('value', data.stixCoreRelationshipsDistribution);
  const countries = map(
    (x) => assoc(
      'level',
      computeLevel(x.value, last(values), head(values) + 1),
      x.entity,
    ),
    data.stixCoreRelationshipsDistribution,
  );
  return (
      <LocationMiniMapTargets
          center={[48.8566969, 2.3514616]}
          countries={countries}
          zoom={2}
      />
  );
};
const LastIngestedAnalysis = () => {
  const classes = useStyles();
  const theme = useTheme();
  const { t, fsd } = useFormatter();
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
  const data = useLazyLoadQuery(dashboardLastStixDomainObjectsQuery, {
    first: 8,
    orderBy: 'created_at',
    orderMode: 'desc',
    types: ['Report', 'Note', 'Opinion'],
  });
  const objects = data.stixDomainObjects;
  if (objects.length === 0) {
    return <NoTableElement/>;
  }
  return <List>
    {objects.edges.map(
      (stixDomainObjectEdge) => {
        const stixDomainObject = stixDomainObjectEdge.node;
        const stixDomainObjectLink = `${resolveLink(stixDomainObject.entity_type)}/${stixDomainObject.id}`;
        return (
              <ListItem key={stixDomainObject.id}
                  dense={true}
                  button={true}
                  classes={{ root: classes.item }}
                  divider={true}
                  component={Link}
                  to={stixDomainObjectLink}>
                <ListItemIcon>
                  <ItemIcon type={stixDomainObject.entity_type} color={theme.palette.primary.main}/>
                </ListItemIcon>
                <div className={classes.itemType}>
                  {t(`entity_${stixDomainObject.entity_type}`)}
                </div>
                <ListItemText primary={<div className={classes.itemText}>
                        {stixDomainObject.name
                        || stixDomainObject.attribute_abstract
                        || truncate(
                          stixDomainObject.content,
                          30,
                        )
                        || stixDomainObject.opinion}
                      </div>}/>
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
                <div style={{ width: 110, maxWidth: 110, minWidth: 110, paddingRight: 20 }}>
                  <ItemMarkings markingDefinitions={pathOr(
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
  </List>;
};
const ObservablesDistribution = () => {
  const classes = useStyles();
  const theme = useTheme();
  const { t } = useFormatter();
  const tickFormatter = (title) => truncate(t(`entity_${title}`), 10);
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
  const data = useLazyLoadQuery(dashboardStixCyberObservablesDistributionQuery, { field: 'entity_type', operation: 'count' });
  const distribution = data.stixCyberObservablesDistribution;
  if (distribution.length === 0) {
    return <NoTableElement/>;
  }
  return <div className={classes.graphContainer}>
    <ResponsiveContainer height={420} width="100%">
      <BarChart layout="vertical" data={distribution}
          margin={{ top: 0, right: 0, bottom: 20, left: 0 }}>
        <XAxis type="number" dataKey="value" stroke={theme.palette.text.primary} allowDecimals={false}/>
        <YAxis stroke={theme.palette.text.primary}
            dataKey="label"
            type="category"
            angle={-30}
            textAnchor="end"
            tickFormatter={tickFormatter}/>
        <CartesianGrid strokeDasharray="2 2" stroke={theme.palette.action.grid}/>
        <Tooltip cursor={{ fill: 'rgba(0, 0, 0, 0.2)', stroke: 'rgba(0, 0, 0, 0.2)', strokeWidth: 2 }}
            contentStyle={{ backgroundColor: 'rgba(255, 255, 255, 0.1)', fontSize: 12, borderRadius: 10 }}/>
        <Bar fill={theme.palette.primary.main}
            dataKey="value"
            barSize={15}>
          {distribution.map((entry, index) => (<Cell key={`cell-${index}`} fill={itemColor(entry.label)}/>))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  </div>;
};
const WorkspaceDashboard = ({ dashboard, timeField }) => {
  const dashboardCustomDashboardQuery = graphql`
    query DashboardCustomDashboardQuery($id: String!) {
      workspace(id: $id) {
        id
        name
        ...Dashboard_workspace
      }
    }
  `;
  const data = useLazyLoadQuery(dashboardCustomDashboardQuery, { id: dashboard });
  if (data.workspace) {
    return <DashboardView workspace={data.workspace} noToolbar={true} timeField={timeField}/>;
  }
  return <ErrorNotFound />;
};
// endregion

const DefaultDashboard = ({ timeField }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const theme = useTheme();
  return <Security needs={[KNOWLEDGE]}
                   placeholder={t('You do not have any access to the knowledge of this OpenCTI instance.')}>
    <Grid container={true} spacing={3}>
      <Grid item={true} xs={3}>
        <Card classes={{ root: classes.card }} style={{ height: 110 }}>
          <Suspense fallback={<Loader variant="inElement" />}>
            <TotalEntitiesCard title={'Total entities'} options={{ endDate: dayAgo() }}
                               Icon={Database} classes={classes} />
          </Suspense>
        </Card>
      </Grid>
      <Grid item={true} xs={3}>
        <Card classes={{ root: classes.card }} style={{ height: 110 }}>
          <Suspense fallback={<Loader variant="inElement" />}>
            <TotalRelationshipsCard title={'Total relationships'}
                                    options={{ type: 'stix-core-relationship', endDate: dayAgo() }}
                                    Icon={GraphOutline} classes={classes} />
          </Suspense>
        </Card>
      </Grid>
      <Grid item={true} xs={3}>
        <Card classes={{ root: classes.card }} style={{ height: 110 }}>
          <Suspense fallback={<Loader variant="inElement" />}>
            <TotalEntitiesCard title={'Total reports'} options={{ types: ['report'], endDate: dayAgo() }}
                               Icon={DescriptionOutlined} classes={classes} />
          </Suspense>
        </Card>
      </Grid>
      <Grid item={true} xs={3}>
        <Card classes={{ root: classes.card }} style={{ height: 110 }}>
          <Suspense fallback={<Loader variant="inElement" />}>
            <TotalObservablesCard title={'Total observables'} options={{ endDate: dayAgo() }}
                                  Icon={HexagonMultipleOutline} classes={classes} />
          </Suspense>
        </Card>
      </Grid>
    </Grid>
    <Grid container={true} spacing={3}>
      <Grid item={true} xs={4}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Top Labels (3 last months)')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2} style={{ height: 300 }}>
          <Suspense fallback={<Loader variant="inElement" />}>
            <TopLabelsCard classes={classes}/>
          </Suspense>
        </Paper>
      </Grid>
      <Grid item={true} xs={8}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Ingested entities')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2} style={{ height: 300 }}>
          <Suspense fallback={<Loader variant="inElement" />}>
            <IngestedEntitiesGraph classes={classes} theme={theme}/>
          </Suspense>
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
            dateAttribute={timeField === 'functional' ? 'start_time' : 'created_at'}
        />
      </Grid>
      <Grid item={true} xs={6}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Targeted countries (3 last months)')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2} style={{ height: 400 }}>
          {/* eslint-disable-next-line max-len */}
          <Suspense fallback={<LocationMiniMapTargets center={[48.8566969, 2.3514616]} zoom={2}/>}>
            <TargetedCountries timeField={timeField}/>
          </Suspense>
        </Paper>
      </Grid>
    </Grid>
    <Grid container={true} spacing={3} style={{ marginTop: 20 }}>
      <Grid item={true} xs={8}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Last ingested analysis (creation date in the platform)')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2} style={{ height: 420 }}>
          <Suspense fallback={<Loader variant="inElement" />}>
            <LastIngestedAnalysis classes={classes} theme={theme}/>
          </Suspense>
        </Paper>
      </Grid>
      <Grid item={true} xs={4}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Observables distribution')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2} style={{ height: 420 }}>
          <Suspense fallback={<Loader variant="inElement" />}>
            <ObservablesDistribution classes={classes} theme={theme}/>
          </Suspense>
        </Paper>
      </Grid>
    </Grid>
  </Security>;
};
const CustomDashboard = ({ dashboard, timeField }) => {
  const { t } = useFormatter();
  return <Security needs={[EXPLORE]}
                   placeholder={t('You do not have any access to the explore part of this OpenCTI instance.')}>
    <Suspense fallback={<Loader />}>
      <WorkspaceDashboard dashboard={dashboard} timeField={timeField}/>
    </Suspense>
  </Security>;
};
const Dashboard = () => {
  const classes = useStyles();
  const [view, saveView] = useViewStorage('view-dashboard');
  const { dashboard = 'default', timeField = 'technical' } = view;
  const handleChangeTimeField = (event) => saveView({ dashboard, timeField: event.target.value });
  const handleChangeDashboard = (event) => saveView({ dashboard: event.target.value, timeField });
  return (
      <div className={classes.root}>
        <TopBar handleChangeTimeField={handleChangeTimeField} timeField={timeField}
                handleChangeDashboard={handleChangeDashboard} dashboard={dashboard}/>
        {dashboard === 'default' ? (
          <DefaultDashboard timeField={timeField}/>
        ) : (
          <CustomDashboard dashboard={dashboard} timeField={timeField}/>
        )}
      </div>
  );
};

export default Dashboard;
